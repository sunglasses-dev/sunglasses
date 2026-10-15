"""`ping` and `notifications/initialized` carry no unread content across.

T2.R14 calls a frame with zero inspectable leaves complete without a scan. The
shortcut was keyed on the METHOD alone, so any content riding on those methods
crossed with no rule reading it:

  a  a ping result or error, a ping request's params, or an initialized
     notification's params, nonempty
  b  a ping result that is a scalar, which the surface lookup read as "nothing
     to inspect" and forwarded

Complete now means the surface is absent or an empty object. Anything else is
read, or refused when the method has no channel to read it on.
"""
import io
import json

import pytest

from sunglasses.proxy import selector

from _proxy_inspect_harness import INJECTION, flagging_scan, frame, make_route


def _ping(request_id=1, **extra):
    return frame(id=request_id, method="ping", **extra)


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


# ── client request direction ───────────────────────────────────────────────

@pytest.mark.parametrize("params", [
    {"note": INJECTION}, {"_meta": {"x": INJECTION}}, [INJECTION], INJECTION,
], ids=["object", "meta", "list", "string"])
def test_a_ping_request_with_content_never_reaches_the_server(tmp_path, params):
    engine, upstream, client, _scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(_ping(1, params=params))
    assert not _crossed(upstream), upstream.bytes
    assert client.messages()[0]["error"]["code"] == -32070


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
