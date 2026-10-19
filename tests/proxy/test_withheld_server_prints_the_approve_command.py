"""A withheld server tells the person at the terminal what to type.

The first refusal of a freshly wrapped server (APPROVAL_REQUIRED) carried the
server id and the snapshot sha in its JSON error, but the proxy's own stderr
stayed empty, so someone who had just wrapped a server and was looking at their
terminal had nothing to act on. The route now offers each (server id, snapshot)
pair to an optional notice callback once, and the proxy command prints the
approve command with both ids filled in.
"""
import io
import shlex
import types

import pytest

from sunglasses.proxy import commands, control as control_module, pump, route as route_module, serve

from route_harness import Sink, CATALOG, Approved, flagging_scan, frame, log

SERVER = "a1b2c3d4e5f6"
SNAPSHOT = "f" * 64


class Record(Approved):
    server_id = SERVER

    def __init__(self, pending=SNAPSHOT):
        self.pending_snapshot = pending

    def _record_or_reason(self):
        return {"snapshot_sha256": "a" * 64}, None

    def may_call(self, tool_name, descriptor_sha256):
        return "APPROVAL_REQUIRED"


def _route(tmp_path, monkeypatch, notice, pending=SNAPSHOT):
    monkeypatch.setattr(
        route_module.activation, "activate",
        lambda store, **kw: types.SimpleNamespace(
            activated=False, provenance="APPROVAL_REQUIRED", detail=None, snapshot=None))
    upstream, client = Sink(), Sink()
    session = pump.Session(strict=False)
    engine = route_module.Route(
        session=session, log=log(tmp_path), upstream_write=upstream,
        client_write=client,
        scan=flagging_scan,
        catalog=CATALOG, approvals=Record(pending),
        control=control_module.Control(session=session, upstream_write=upstream),
        server_identity=SERVER, approval_notice=notice)
    return engine, client


def _call(engine, request_id=1):
    engine.client_frame(frame(id=request_id, method="tools/call",
                              params={"name": "echo", "arguments": {}}))


def test_the_refusal_prints_the_exact_approve_command_once(tmp_path, monkeypatch):
    err = io.StringIO()
    engine, client = _route(tmp_path, monkeypatch, serve.approval_notice(err))
    _call(engine, 1)
    _call(engine, 2)
    answers = client.messages()
    assert [a["error"]["data"]["reason_code"] for a in answers] == ["APPROVAL_REQUIRED"] * 2
    assert answers[0]["error"]["data"]["server_id"] == SERVER
    lines = err.getvalue().splitlines()
    assert len(lines) == 1, lines
    assert f"sunglasses proxy approve {SERVER} --snapshot {SNAPSHOT}" in lines[0]
    assert "--state-root" not in lines[0]
    assert "withheld until you approve" in lines[0]


def test_a_second_snapshot_is_announced_again(tmp_path, monkeypatch):
    err = io.StringIO()
    engine, _ = _route(tmp_path, monkeypatch, serve.approval_notice(err))
    _call(engine, 1)
    engine.approvals.pending_snapshot = "e" * 64
    _call(engine, 2)
    assert len(err.getvalue().splitlines()) == 2
    assert "--snapshot " + "e" * 64 in err.getvalue()


def test_the_printed_command_is_one_the_approve_command_accepts(tmp_path, monkeypatch):
    """Round trip: split the printed line, run it. It must get as far as looking
    for the capture (nothing was captured here, so it says so) rather than
    answering with its usage text."""
    err = io.StringIO()
    engine, _ = _route(tmp_path, monkeypatch, serve.approval_notice(err, root=str(tmp_path)))
    _call(engine)
    line = err.getvalue().splitlines()[0]
    argv = shlex.split(line.split("run: ", 1)[1].split(" (it shows", 1)[0])
    assert argv[:3] == ["sunglasses", "proxy", "approve"]
    out, errs = io.StringIO(), io.StringIO()
    rc = commands.main(argv[2:], stdout=out, stderr=errs)
    assert "no stored capture" in errs.getvalue(), (rc, errs.getvalue())


def test_a_custom_state_root_is_in_the_command_and_quoted(tmp_path, monkeypatch):
    err = io.StringIO()
    root = str(tmp_path / "my state")
    engine, _ = _route(tmp_path, monkeypatch, serve.approval_notice(err, root=root))
    _call(engine)
    assert f"--state-root {shlex.quote(root)}" in err.getvalue()


def test_no_pending_snapshot_prints_nothing(tmp_path, monkeypatch):
    err = io.StringIO()
    engine, client = _route(tmp_path, monkeypatch, serve.approval_notice(err), pending=None)
    _call(engine)
    assert err.getvalue() == ""
    assert client.messages()[0]["error"]["data"]["reason_code"] == "APPROVAL_REQUIRED"


def test_a_route_with_no_notice_is_silent_as_before(tmp_path, monkeypatch):
    engine, client = _route(tmp_path, monkeypatch, None)
    _call(engine)
    assert client.messages()[0]["error"]["data"]["server_id"] == SERVER


def test_a_failing_notice_never_costs_the_client_its_answer(tmp_path, monkeypatch):
    def broken(server_id, snapshot):
        raise BrokenPipeError("stderr closed")

    engine, client = _route(tmp_path, monkeypatch, broken)
    _call(engine)
    assert client.messages()[0]["error"]["data"]["reason_code"] == "APPROVAL_REQUIRED"


def test_only_approval_required_announces(tmp_path, monkeypatch):
    seen = []
    engine, _ = _route(tmp_path, monkeypatch, lambda *ids: seen.append(ids))
    assert engine._approval_hint("UNINSPECTED_METHOD") == {}
    assert seen == []
