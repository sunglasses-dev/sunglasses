"""A list or an object where an id or a tool name belongs is refused, not raised.

Two client controlled values were used as dict and set keys before their type
was checked, so a list or an object there raised TypeError out of
`Route.client_frame`, and the serve loop closed the session as an instrument
fault, which misnames a malformed client frame.

  cancel:    `params.requestId` as a list or an object
  tools/call: `params.name` as an object or a list
"""
import pytest

from route_harness import frame, make_route


@pytest.mark.parametrize("request_id", [[1], {"a": 1}])
def test_cancel_with_an_unhashable_request_id_does_not_raise(tmp_path, request_id):
    engine, upstream, client, scans = make_route(tmp_path)
    try:
        engine.client_frame(frame(method="notifications/cancelled",
                                  params={"requestId": request_id}))
    except TypeError as failure:
        pytest.fail(f"client_frame raised out of the reader: {failure!r}")
    closed = engine.session.closed_with()
    assert closed is None or closed[0] == "MALFORMED_CLIENT"


@pytest.mark.parametrize("name", [{"a": 1}, ["echo"]])
def test_tool_call_with_an_unhashable_name_does_not_raise(tmp_path, name):
    engine, upstream, client, scans = make_route(tmp_path)
    try:
        engine.client_frame(frame(id=1, method="tools/call",
                                  params={"name": name, "arguments": {}}))
    except TypeError as failure:
        pytest.fail(f"client_frame raised out of the reader: {failure!r}")
    assert upstream.bytes == b""
    assert client.messages(), "the client was owed one answer"
