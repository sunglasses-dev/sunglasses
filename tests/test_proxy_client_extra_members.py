"""An extra top-level member on a client frame is content, whatever the method.

The scan of a client frame read `params` and nothing else. A `tools/call`,
`initialize`, `resources/read`, `prompts/get` or forwarded notification with a
member beside `params` was scanned (clean) and then forwarded whole, so the
member reached the server with no rule reading it. The result direction already
reads every member; this is the same rule for the client direction.

`tools/list` is not in the matrix: the client's frame is never forwarded, one
request becomes the proxy's own list calls, so no member of it can cross.
`notifications/cancelled` is honoured locally and is not forwarded either.
"""
import json

import pytest

from sunglasses.proxy import bounds, selector

from _proxy_inspect_harness import INJECTION, flagging_scan, frame, make_route

# method -> (request id or None, params the method normally carries)
_REQUESTS = {
    "initialize": (1, {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "lab", "version": "0"}}),
    "tools/call": (2, {"name": "echo", "arguments": {"text": "hi"}}),
    "resources/read": (3, {"uri": "file:///a"}),
    "prompts/get": (4, {"name": "p"}),
}
_NOTIFICATIONS = {
    "notifications/roots/list_changed": None,
    "notifications/initialized": {"note": "hi"},
}
_ALL = {**_REQUESTS, **{m: (None, p) for m, p in _NOTIFICATIONS.items()}}


def _rows(tmp_path):
    rows = []
    for path in (tmp_path / "receipts").glob("*.jsonl"):
        rows += [json.loads(line) for line in path.read_text().splitlines()]
    return rows


def _crossed(sink):
    return INJECTION.encode() in sink.bytes


def _frame(method, extra, *, with_params=True):
    request_id, params = _ALL[method]
    members = dict(extra)
    if request_id is not None:
        members["id"] = request_id
    if with_params and params is not None:
        members["params"] = params
    return frame(method=method, **members)


_EXTRAS = [{"note": INJECTION}, {"_meta": {"x": INJECTION}},
           {"arguments": {"text": INJECTION}}]
_EXTRA_IDS = ["text", "metadata", "lookalike-key"]


@pytest.mark.parametrize("method", sorted(_ALL))
@pytest.mark.parametrize("extra", _EXTRAS, ids=_EXTRA_IDS)
def test_a_flagged_extra_member_never_reaches_the_server(
        tmp_path, method, extra):
    engine, upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(_frame(method, extra))
    assert not _crossed(upstream), upstream.bytes
    assert len(scans) == 1 and scans[0]["channel"] == "message"
    assert "PROHIBITED_CONTENT" in [r.get("reason_code") for r in _rows(tmp_path)
                                    if r["kind"] == "SETTLED"]
    if method in _REQUESTS:
        answers = client.messages()
        assert len(answers) == 1 and answers[0]["id"] == _REQUESTS[method][0]
        assert answers[0]["error"]["data"]["reason_code"] == "PROHIBITED_CONTENT"


@pytest.mark.parametrize("method", sorted(_NOTIFICATIONS))
def test_a_flagged_extra_member_on_a_notification_without_params(
        tmp_path, method):
    engine, upstream, _client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(_frame(method, {"note": INJECTION}, with_params=False))
    assert not _crossed(upstream) and len(scans) == 1


@pytest.mark.parametrize("method", sorted(_ALL))
@pytest.mark.parametrize("extra", [{"note": "hello"}, {"_meta": {"x": 1}}],
                         ids=["text", "metadata"])
def test_a_clean_extra_member_is_read_then_forwarded_byte_exact(
        tmp_path, method, extra):
    engine, upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    raw = _frame(method, extra)
    engine.client_frame(raw)
    assert len(scans) == 1 and scans[0]["channel"] == "message"
    surface = json.dumps(scans[0]["params"])
    assert all(key in surface for key in extra)
    assert upstream.bytes == raw and client.bytes == b""


@pytest.mark.parametrize("method", sorted(_ALL))
def test_a_frame_with_no_extra_member_is_scanned_exactly_as_before(
        tmp_path, method):
    """Control. The surface of an ordinary frame is its params, unwrapped."""
    _request_id, params = _ALL[method]
    engine, upstream, _client, scans = make_route(tmp_path, scan=flagging_scan)
    raw = _frame(method, {})
    engine.client_frame(raw)
    if params is None:
        assert upstream.bytes == raw
        return
    assert [s["params"] for s in scans] == [params]
    assert upstream.bytes == raw


@pytest.mark.parametrize("method", sorted(_REQUESTS))
def test_an_extra_member_counts_toward_the_content_bound(tmp_path, method):
    engine, upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(_frame(
        method, {"note": "a" * (bounds.CONTENT_BYTES + 1)}))
    assert upstream.bytes == b"" and scans == []
    answers = client.messages()
    assert len(answers) == 1 and answers[0]["error"]["data"]["reason_code"] \
        == "OVER_BUDGET"


@pytest.mark.parametrize("method", sorted(_ALL))
def test_the_surface_names_the_params_and_every_extra_member(method):
    _request_id, params = _ALL[method]
    message = {"jsonrpc": "2.0", "method": method, "note": "n"}
    if params is not None:
        message["params"] = params
    surface = selector.client_surface(method, message)
    assert surface["note"] == "n"
    if params is not None:
        assert surface["params"] == params


@pytest.mark.parametrize("method", sorted(_ALL))
def test_the_surface_without_an_extra_member_is_the_params(method):
    _request_id, params = _ALL[method]
    message = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        message["params"] = params
    assert selector.client_surface(method, message) == (params or {})
