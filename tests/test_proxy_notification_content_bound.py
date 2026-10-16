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


def _build(method, placement, total, filler="a"):
    """A no-id frame whose selected surface is exactly `total` content bytes."""
    def text(n):
        return filler * n

    def message(first, second):
        msg = {"method": method}
        if placement in ("params", "split"):
            msg["params"] = {"data": text(first)}
        if placement in ("extra", "split"):
            msg["extra"] = text(second)
        return msg

    base = _size(method, message(0, 0))
    spare = total - base
    assert spare >= 0
    if placement == "params":
        parts = (spare, 0)
    elif placement == "extra":
        parts = (0, spare)
    else:
        parts = (spare // 2, spare - spare // 2)
    built = message(*parts)
    assert _size(method, built) == total
    return frame(**built)


def _size(method, message):
    return selector.content_bytes(
        selector.bound_surface(method, dict(jsonrpc="2.0", **message)))


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
    """A multibyte string is three times the budget a character count would
    give it. The cap and the byte just past it, built from two-byte letters."""
    for total, forwarded in ((CAP, True), (CAP + 1, False)):
        engine, upstream, _client, scans = make_route(tmp_path / str(total))
        method = "notifications/message"
        base = _size(method, {"method": method, "params": {"data": ""}}
                     if placement == "params"
                     else {"method": method, "extra": ""})
        spare = total - base
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


def test_a_request_with_an_oversized_extra_is_refused_too(tmp_path):
    """The count is shared with the request path, so an oversized top-level
    member on a request is now refused the way oversized params already were."""
    engine, upstream, client, scans = make_route(tmp_path)
    engine.client_frame(frame(id=5, method="resources/read",
                              params={"uri": "file:///a"},
                              extra="a" * (CAP + 1)))
    assert upstream.bytes == b"" and scans == []
    answers = client.messages()
    assert len(answers) == 1 and answers[0]["id"] == 5
    assert answers[0]["error"]["data"]["reason_code"] == "OVER_BUDGET"


def test_a_request_with_a_small_extra_is_forwarded_and_its_scan_is_unchanged(
        tmp_path):
    """Counted, not scanned: the scan still reads `params` only."""
    engine, upstream, _client, scans = make_route(tmp_path)
    engine.client_frame(frame(id=5, method="resources/read",
                              params={"uri": "file:///a"}, extra="hello"))
    assert len(scans) == 1
    assert scans[0]["params"] == {"uri": "file:///a"}
    assert json.loads(upstream.bytes)["extra"] == "hello"
