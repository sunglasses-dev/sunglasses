"""A call with no usable tool name is refused before anything is sent upstream.

The approval check started the activation (a listing request written to the
server) and only then looked the name up. A name that is missing or null passed
the type check meant for a list or an object, so a client could make the proxy
write a control request upstream for a call that could never be approved.

The route here has a real control channel over a recording sink, so a request
that reaches the activation shows up as bytes on the upstream side.
"""
import types

import pytest

from sunglasses.proxy import control as control_module, pump, route as route_module

from route_harness import Sink, CATALOG, Approved, frame, log, make_route


class Record(Approved):
    """An approval store that has a record on disk and counts what is asked."""
    server_id = "server"

    def __init__(self):
        self.asked = []

    def _record_or_reason(self):
        return {"snapshot_sha256": "a" * 64}, None

    def may_call(self, tool_name, descriptor_sha256):
        self.asked.append(tool_name)
        return None


def _count_activations(monkeypatch):
    """Count the activations. The real one writes a listing request upstream,
    which the sink assertions below would also show."""
    calls = []

    def activate(store, *, list_pages, scan, server_identity, collect=None):
        calls.append(server_identity)
        return types.SimpleNamespace(activated=False, provenance="APPROVAL_REQUIRED",
                                     detail=None, snapshot=None)

    monkeypatch.setattr(route_module.activation, "activate", activate)
    return calls


def _route(tmp_path):
    upstream, client = Sink(), Sink()
    session = pump.Session(strict=False)
    approvals = Record()
    engine = route_module.Route(
        session=session, log=log(tmp_path), upstream_write=upstream,
        client_write=client,
        scan=lambda params, *, channel, binding, content_bytes: None,
        catalog=CATALOG, approvals=approvals,
        control=control_module.Control(session=session,
                                       upstream_write=upstream),
        server_identity="server")
    return engine, upstream, client, approvals


@pytest.mark.parametrize("params", [
    {"arguments": {}},                      # name missing
    {"name": None, "arguments": {}},        # name null
    {"name": "", "arguments": {}},          # name empty
    {"name": 7, "arguments": {}},
    {"name": True, "arguments": {}},
    {"name": ["echo"], "arguments": {}},
    {"name": {"a": 1}, "arguments": {}},
    None,                                   # no params at all
    [],                                     # params of the wrong type
])
def test_no_usable_name_starts_no_activation_and_writes_nothing_upstream(
        tmp_path, monkeypatch, params):
    activations = _count_activations(monkeypatch)
    engine, upstream, client, approvals = _route(tmp_path)
    message = {"id": 1, "method": "tools/call"}
    if params is not None:
        message["params"] = params
    engine.client_frame(frame(**message))
    assert activations == []
    assert upstream.bytes == b"", upstream.bytes
    assert approvals.asked == []
    answers = client.messages()
    assert len(answers) == 1, answers
    assert answers[0]["id"] == 1
    assert answers[0]["error"]["data"]["reason_code"] == "APPROVAL_REQUIRED"
    assert engine.session.closed_with() is None


def test_a_real_name_still_reaches_the_activation(tmp_path, monkeypatch):
    """Control: the check does not turn the activation off for a good call."""
    activations = _count_activations(monkeypatch)
    engine, upstream, client, approvals = _route(tmp_path)
    engine.client_frame(frame(id=1, method="tools/call",
                              params={"name": "echo", "arguments": {}}))
    assert activations == ["server"]
