"""A client `initialize` whose protocol offer is not a string never reaches the server.

`handshake.negotiate` judged only the version the SERVER answered with. The
version the CLIENT offered was never looked at, so `"protocolVersion": 7` (or
null, a list, an object, a boolean) went upstream and whatever the server did
with it succeeded: the handshake the whole session identity rests on began from a
frame the proxy had not read.

Only the TYPE is refused here. A string the supported set does not name still
goes upstream, because the server answers with a version it does support and the
client decides whether to continue (MCP lifecycle, version negotiation).
"""
import json

import pytest

from _proxy_inspect_harness import frame, make_route


def _offer(value, request_id=1):
    return frame(id=request_id, method="initialize",
                 params={"protocolVersion": value, "capabilities": {},
                         "clientInfo": {"name": "t", "version": "1"}})


@pytest.mark.parametrize("value", [7, 1.5, None, True, ["2025-11-25"],
                                   {"v": "2025-11-25"}])
def test_a_non_string_offer_is_not_forwarded(tmp_path, value):
    engine, upstream, client, _scans = make_route(tmp_path)
    engine.client_frame(_offer(value))
    assert upstream.bytes == b"", upstream.bytes


@pytest.mark.parametrize("value", [7, None, ["2025-11-25"]])
def test_a_non_string_offer_is_answered_once_by_the_proxy(tmp_path, value):
    engine, _upstream, client, _scans = make_route(tmp_path)
    engine.client_frame(_offer(value, request_id=9))
    answers = client.messages()
    assert len(answers) == 1, answers
    assert answers[0]["id"] == 9
    assert answers[0]["error"]["data"]["reason_code"] == "UNSUPPORTED_PROTOCOL"


def test_a_non_string_offer_closes_the_session(tmp_path):
    engine, _upstream, _client, _scans = make_route(tmp_path)
    engine.client_frame(_offer(7))
    assert engine.session.closed_with() is not None


@pytest.mark.parametrize("value", ["2025-11-25", "2024-11-05", "2026-07-28",
                                   "2025-11-25-beta", ""])
def test_a_string_offer_still_goes_upstream(tmp_path, value):
    """Controls: the string offers are untouched, supported or not."""
    engine, upstream, _client, _scans = make_route(tmp_path)
    engine.client_frame(_offer(value))
    assert json.loads(upstream.bytes)["params"]["protocolVersion"] == value
