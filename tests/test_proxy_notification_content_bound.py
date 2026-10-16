"""A client notification over the content bound is dropped before any scan.

AR09 put the content bound on client REQUESTS (`_client_request`), so a request
carrying more than the cap never reaches the worker or the server. A
notification takes `_client_notification`, which called `_inspect` directly: an
oversized one was scanned and forwarded. ASTRA's #393 r1 verdict measured it
(all 14 admitted no-id route shapes forwarded after one scan above the bound).

A notification has no response, so the outcome is the same one an unknown
notification gets: dropped with one receipt, nothing written to either side.
"""
import json

import pytest

from sunglasses.proxy import bounds, selector

from _proxy_inspect_harness import frame, make_route

NOTIFICATIONS = [
    "notifications/message",
    "notifications/progress",
    "notifications/resources/updated",
    "notifications/roots/list_changed",
    "notifications/tools/list_changed",
    "notifications/prompts/list_changed",
    "notifications/resources/list_changed",
]


def _note(method, text):
    return frame(method=method, params={"data": text})


def _rows(tmp_path):
    rows = []
    for path in (tmp_path / "receipts").glob("*.jsonl"):
        rows += [json.loads(line) for line in path.read_text().splitlines()]
    return rows


def _size_of(method, text):
    message = json.loads(_note(method, text))
    return selector.content_bytes(selector.client_surface(method, message))


@pytest.mark.parametrize("method", NOTIFICATIONS)
def test_an_oversized_notification_is_not_scanned_or_forwarded(tmp_path, method):
    engine, upstream, client, scans = make_route(tmp_path)
    text = "a" * (bounds.CONTENT_BYTES + 1)
    assert _size_of(method, text) > bounds.CONTENT_BYTES
    engine.client_frame(_note(method, text))
    assert upstream.bytes == b"", "the oversized notification reached the server"
    assert scans == [], "the worker was asked to scan more than the bound"
    assert client.bytes == b"", "a notification gets no answer"


@pytest.mark.parametrize("method", NOTIFICATIONS)
def test_the_drop_is_receipted_once_with_the_content_budget(tmp_path, method):
    engine, _upstream, _client, _scans = make_route(tmp_path)
    engine.client_frame(_note(method, "a" * (bounds.CONTENT_BYTES + 1)))
    settled = [row for row in _rows(tmp_path) if row["kind"] == "SETTLED"]
    assert len(settled) == 1, settled
    assert settled[0]["reason_code"] == "OVER_BUDGET"
    assert settled[0]["rule"] == "S3"
    assert settled[0]["budget"] == "content"


def test_an_oversized_extra_on_an_initialized_notification_is_dropped(tmp_path):
    """`initialized` has a zero-leaf shortcut; an extra top-level member takes it
    off the shortcut, and that member is what the bound must read."""
    engine, upstream, _client, scans = make_route(tmp_path)
    engine.client_frame(frame(method="notifications/initialized",
                              extra="a" * (bounds.CONTENT_BYTES + 1)))
    assert upstream.bytes == b"" and scans == []


def test_the_session_survives_an_oversized_notification(tmp_path):
    engine, _upstream, _client, _scans = make_route(tmp_path)
    engine.client_frame(_note("notifications/message",
                              "a" * (bounds.CONTENT_BYTES + 1)))
    assert engine.session.closed_with() is None


@pytest.mark.parametrize("method", NOTIFICATIONS)
def test_a_notification_exactly_at_the_bound_is_still_scanned_and_forwarded(
        tmp_path, method):
    """Inclusive, like the request side."""
    engine, upstream, _client, scans = make_route(tmp_path)
    base = _size_of(method, "")
    text = "a" * (bounds.CONTENT_BYTES - base)
    assert _size_of(method, text) == bounds.CONTENT_BYTES
    engine.client_frame(_note(method, text))
    assert len(scans) == 1
    assert json.loads(upstream.bytes)["method"] == method


def test_a_small_notification_is_unchanged(tmp_path):
    engine, upstream, _client, scans = make_route(tmp_path)
    engine.client_frame(_note("notifications/message", "hello"))
    assert len(scans) == 1 and upstream.bytes != b""
