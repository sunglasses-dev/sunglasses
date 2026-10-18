"""A client frame with no id, over the content bound, is dropped before any scan.

AR09 put the content bound on client REQUESTS (`_client_request`), so a request
carrying more than the cap never reaches the worker or the server. A
notification takes `_client_notification`, which called `_inspect` directly: an
oversized one was scanned and forwarded. The review of #393 measured it: all 14
admitted no-id route shapes forwarded after one scan above the bound.

Two things closed it. The notification path now applies the bound before
`_inspect`, and the bound now counts through `selector.bound_surface`, which adds
every top-level member beside the envelope to what `client_surface` returns: a
member other than `params` is not scanned for most methods, so counting only the
scanned surface let an oversized one through on twelve of the fourteen shapes.
The members are counted here, not scanned; what a scan reads is unchanged.

A notification has no response, so the outcome is the one an unknown notification
gets: dropped with one SETTLED receipt, nothing written to either side. A frame
with no id that is a request-method shape (initialize, tools/call, ...) takes the
same path, so it is covered the same way.

What this does NOT do: an oversized `notifications/initialized` is withheld from
the server like any other, so a server that waits for it needs a later valid one.
"""
import json

import pytest

from sunglasses.proxy import bounds, selector

from _proxy_inspect_harness import frame, make_route

# The 14 no-id shapes the review enumerated: six request-method names sent with
# no id, then eight notification names.
SHAPES = [
    "initialize",
    "tools/call",
    "tools/list",
    "resources/read",
    "prompts/get",
    "ping",
    "notifications/initialized",
    "notifications/message",
    "notifications/progress",
    "notifications/prompts/list_changed",
    "notifications/resources/list_changed",
    "notifications/resources/updated",
    "notifications/roots/list_changed",
    "notifications/tools/list_changed",
]
CAP = bounds.CONTENT_BYTES
EDGES = {"under": CAP - 1, "at": CAP, "over": CAP + 1}
PLACEMENTS = ["params", "extra", "split"]
TOOL_NAME = "t"


def _counted(message):
    """The decoded content bytes a frame carries, worked out here and not through
    the selector under test: the only string leaves `_build` puts in a frame are
    `params.data`, `params.name` (on a `tools/call` request, see `_build`) and the
    top-level `extra`; the envelope (`jsonrpc`, `id`, `method`) and every key name
    are not content."""
    params = message.get("params", {})
    return (len(params.get("data", "").encode("utf-8"))
            + len(params.get("name", "").encode("utf-8"))
            + len(message.get("extra", "").encode("utf-8")))


def _build(method, placement, total, filler="a", request_id=None):
    """A frame whose counted content is exactly `total` bytes, by construction: the
    filler is one byte a character and it is the only content in the frame. No id
    by default; `request_id` makes it a request. A `tools/call` request names its
    tool (one byte, counted, taken out of the filler): a call with no usable name is
    refused before the content bound is reached, which would hide what these tests
    pin."""
    named = method == "tools/call" and request_id is not None
    if named:
        total -= len(TOOL_NAME)

    def text(n):
        return filler * n

    def message(first, second):
        msg = {"method": method}
        if request_id is not None:
            msg["id"] = request_id
        if placement in ("params", "split"):
            msg["params"] = {"data": text(first)}
        if named:
            msg.setdefault("params", {})["name"] = TOOL_NAME
        if placement in ("extra", "split"):
            msg["extra"] = text(second)
        return msg

    spare = total
    if placement == "params":
        parts = (spare, 0)
    elif placement == "extra":
        parts = (0, spare)
    else:
        parts = (spare // 2, spare - spare // 2)
    built = message(*parts)
    assert _counted(built) == total + (len(TOOL_NAME) if named else 0)
    return frame(**built)


def _settled(tmp_path):
    rows = []
    for path in (tmp_path / "receipts").glob("*.jsonl"):
        rows += [json.loads(line) for line in path.read_text().splitlines()]
    return [row for row in rows if row["kind"] == "SETTLED"]


@pytest.mark.parametrize("edge", ["over"])
@pytest.mark.parametrize("placement", PLACEMENTS)
@pytest.mark.parametrize("method", SHAPES)
def test_an_oversized_frame_is_dropped_whole(tmp_path, method, placement, edge):
    engine, upstream, client, scans = make_route(tmp_path)
    engine.client_frame(_build(method, placement, EDGES[edge]))
    assert upstream.bytes == b"", "the oversized frame reached the server"
    assert scans == [], "the worker was asked to scan more than the bound"
    assert client.bytes == b"", "a frame with no id gets no answer"
    settled = _settled(tmp_path)
    assert len(settled) == 1, settled
    assert settled[0]["reason_code"] == "OVER_BUDGET"
    assert settled[0]["rule"] == "S3"
    assert settled[0]["budget"] == "content"


@pytest.mark.parametrize("edge", ["under", "at"])
@pytest.mark.parametrize("placement", PLACEMENTS)
@pytest.mark.parametrize("method", SHAPES)
def test_a_frame_at_or_under_the_bound_is_still_scanned_and_forwarded(
        tmp_path, method, placement, edge):
    """Inclusive, like the request side: the cap itself is admitted."""
    engine, upstream, _client, scans = make_route(tmp_path)
    raw = _build(method, placement, EDGES[edge])
    engine.client_frame(raw)
    assert len(scans) == 1, scans
    assert json.loads(upstream.bytes) == json.loads(raw)
    assert [row["reason_code"] for row in _settled(tmp_path)
            if row["reason_code"] == "OVER_BUDGET"] == []


@pytest.mark.parametrize("placement", ["params", "extra"])
def test_the_bound_counts_decoded_bytes_not_characters(tmp_path, placement):
    """A two-byte character counts twice what a character count would give it. The
    cap and the byte just past it, built from two-byte characters (and one
    one-byte character when the total is odd)."""
    for total, forwarded in ((CAP, True), (CAP + 1, False)):
        engine, upstream, _client, scans = make_route(tmp_path / str(total))
        method = "notifications/message"
        spare = total
        text = "é" * (spare // 2) + "a" * (spare % 2)
        assert len(text.encode()) == spare
        body = ({"params": {"data": text}} if placement == "params"
                else {"extra": text})
        engine.client_frame(frame(method=method, **body))
        assert bool(upstream.bytes) is forwarded
        assert len(scans) == (1 if forwarded else 0)


def test_an_oversized_initialized_notification_is_withheld_and_a_later_one_goes(
        tmp_path):
    """The drop is receipted and answers nothing; the proxy stays usable, and
    the next valid initialized notification reaches the server. Without that
    later one the server never sees the handshake finish."""
    engine, upstream, client, scans = make_route(tmp_path)
    engine.client_frame(_build("notifications/initialized", "extra", CAP + 1))
    assert upstream.bytes == b"" and client.bytes == b"" and scans == []
    assert len(_settled(tmp_path)) == 1
    assert engine.session.closed_with() is None
    engine.client_frame(frame(method="notifications/initialized"))
    assert json.loads(upstream.bytes)["method"] == "notifications/initialized"


def test_an_initialized_notification_with_a_small_extra_is_unchanged(tmp_path):
    """The paired control for the oversized initialized case above."""
    engine, upstream, _client, scans = make_route(tmp_path)
    engine.client_frame(frame(method="notifications/initialized", extra="hello"))
    assert len(scans) == 1
    assert json.loads(upstream.bytes)["extra"] == "hello"


def test_the_session_survives_an_oversized_notification_and_works_after(tmp_path):
    engine, upstream, _client, scans = make_route(tmp_path)
    engine.client_frame(_build("notifications/message", "params", CAP + 1))
    # The drop happened: nothing crossed and one budget settlement exists.
    assert upstream.bytes == b"" and scans == []
    assert len(_settled(tmp_path)) == 1
    assert engine.session.closed_with() is None
    # And the session still carries the next notification.
    engine.client_frame(frame(method="notifications/message",
                              params={"data": "hello"}))
    assert json.loads(upstream.bytes)["params"] == {"data": "hello"}
    assert len(scans) == 1


@pytest.mark.parametrize("method", SHAPES)
def test_the_envelope_is_not_counted_on_the_notification_path(tmp_path, method):
    """Exactly the cap of content is admitted, however long the method name is.
    `method` is a string value that `content_bytes` counts unless the surface
    leaves it out (`jsonrpc` and `id` it skips by key itself). If `bound_surface`
    let the envelope in, the same frame would be over the cap by the name's bytes
    and dropped, so a selector that widens into the envelope fails here, at the
    route, and not only in a builder."""
    assert len(method) > 0
    engine, upstream, _client, scans = make_route(tmp_path)
    raw = _build(method, "extra", CAP)
    assert _counted(json.loads(raw)) == CAP
    engine.client_frame(raw)
    assert len(scans) == 1, "the envelope was counted toward the content bound"
    assert json.loads(upstream.bytes) == json.loads(raw)


# What the REQUEST path does for the same 14 method names sent WITH an id, in the
# order params/extra/split x under/at/over. F = forwarded after one scan, N = not
# forwarded and not scanned (an existing admission or special path, or the
# content bound). On main the oversized top-level extra (slots 5 and 8) was
# forwarded on eight shapes; the request guard now counts it, so those cells are
# N. Nothing else moved: params over the cap was already N, every at-or-under
# cell is as it was, and the shapes that never reach the guard are N throughout.
REQUEST_NOW = {
    "initialize": "FFNFFNFFN",
    "tools/call": "FFNFFNFFN",
    "tools/list": "NNNNNNNNN",
    "resources/read": "FFNFFNFFN",
    "prompts/get": "FFNFFNFFN",
    "ping": "FFNFFNFFN",
    "notifications/initialized": "FFNFFNFFN",
    "notifications/message": "FFNFFNFFN",
    "notifications/progress": "FFNFFNFFN",
    "notifications/prompts/list_changed": "NNNNNNNNN",
    "notifications/resources/list_changed": "NNNNNNNNN",
    "notifications/resources/updated": "NNNNNNNNN",
    "notifications/roots/list_changed": "FFNFFNFFN",
    "notifications/tools/list_changed": "FFNFFNFFN",
}
# The cells that changed against main: extra-over and split-over on a shape that
# was forwarded there.
REQUEST_MOVED = {"initialize", "tools/call", "resources/read", "prompts/get",
                 "notifications/message", "notifications/progress",
                 "notifications/roots/list_changed",
                 "notifications/tools/list_changed"}


@pytest.mark.parametrize("edge", ["under", "at", "over"])
@pytest.mark.parametrize("placement", PLACEMENTS)
@pytest.mark.parametrize("method", SHAPES)
def test_the_request_path_counts_a_top_level_extra(tmp_path, method, placement, edge):
    engine, upstream, _client, scans = make_route(tmp_path)
    raw = _build(method, placement, EDGES[edge], request_id=7)
    engine.client_frame(raw)
    slot = PLACEMENTS.index(placement) * 3 + list(EDGES).index(edge)
    expected = REQUEST_NOW[method][slot]
    assert ("F" if upstream.bytes else "N") == expected
    assert len(scans) == (1 if expected == "F" else 0)
    if scans:
        # The scan reads what it always read, not the wider counted surface.
        message = json.loads(raw)
        assert scans[0]["params"] == selector.client_surface(method, message)


@pytest.mark.parametrize("placement", ["extra", "split"])
@pytest.mark.parametrize("method", sorted(REQUEST_MOVED))
def test_an_oversized_extra_on_a_request_is_answered_over_budget(
        tmp_path, method, placement):
    """The cells that moved are refused the way an oversized `params` is: one
    answer to the caller, carrying the id and the budget, nothing to the server,
    no scan."""
    engine, upstream, client, scans = make_route(tmp_path)
    engine.client_frame(_build(method, placement, CAP + 1, request_id=7))
    assert upstream.bytes == b"" and scans == []
    answers = client.messages()
    assert len(answers) == 1, answers
    assert answers[0]["id"] == 7
    assert answers[0]["error"]["data"]["reason_code"] == "OVER_BUDGET"
    assert answers[0]["error"]["data"].get("budget") == "content"


@pytest.mark.parametrize("edge", ["under", "at", "over"])
@pytest.mark.parametrize("with_params", [False, True])
@pytest.mark.parametrize("method", sorted(REQUEST_MOVED))
def test_several_extras_on_a_request_share_one_content_bound(
        tmp_path, method, with_params, edge):
    """Two extras that are each far under the cap but together over it are
    refused; the same two at or under the cap are forwarded after one scan. A
    guard that counted only the first extra would forward the over case."""
    total = EDGES[edge]
    message = {"id": 7, "method": method,
               "extra": "a" * (CAP // 2), "second": "b" * (total - CAP // 2)}
    if with_params:
        message["params"] = {"data": "c"}
        message["second"] = message["second"][:-1]
    if method == "tools/call":
        # a call with no usable name is refused before the bound is reached
        message.setdefault("params", {})["name"] = TOOL_NAME
        message["second"] = message["second"][:-len(TOOL_NAME)]
    params = message.get("params", {})
    assert (len(message["extra"]) + len(message["second"]) + len(params.get("data", ""))
            + len(params.get("name", ""))) == total
    engine, upstream, client, scans = make_route(tmp_path)
    raw = frame(**message)
    engine.client_frame(raw)
    if total <= CAP:
        assert upstream.bytes == raw and len(scans) == 1 and client.bytes == b""
    else:
        assert upstream.bytes == b"" and scans == []
        answers = client.messages()
        assert len(answers) == 1 and answers[0]["id"] == 7
        data = answers[0]["error"]["data"]
        assert (data["reason_code"], data["rule"], data["budget"]) == \
            ("OVER_BUDGET", "S3", "content")
        settled = _settled(tmp_path)
        assert len(settled) == 1 and settled[0]["reason_code"] == "OVER_BUDGET"
    engine.log.close()
