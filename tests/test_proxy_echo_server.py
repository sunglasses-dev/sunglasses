"""The bundled echo server, specified before it exists.

T10.R1's self test spawns the installed artifact against this, and T12.R1
requires the acceptance runs to go through real pipes and real upstreams rather
than a mock that agrees with us. So this is a small MCP stdio server whose only
interesting property is that it is REAL: a separate process, its own stdin and
stdout, and no shared memory with anything measuring it.

It carries one instrument. Every raw line it receives is appended to the file
named by SUNGLASSES_ECHO_INGRESS, flushed immediately. That file is how a test
answers the only question that distinguishes mediation from a log line claiming
mediation: how many bytes of the protected payload reached the server. Zero, or
it did not work. Reading that from inside the proxy would be the proxy grading
itself, which is why it is written by the process on the far side.
"""
import json
import os
import subprocess
import sys

import pytest

pytest.importorskip("sunglasses.proxy.echo_server",
                    reason="the echo server is the slice being specified")


def _talk(frames, tmp_path, timeout=20):
    """Run the server as a real process and collect what it says back."""
    ingress = tmp_path / "ingress.log"
    env = dict(os.environ, SUNGLASSES_ECHO_INGRESS=str(ingress))
    proc = subprocess.run(
        [sys.executable, "-m", "sunglasses.proxy.echo_server"],
        input=b"".join(frames), capture_output=True, env=env, timeout=timeout)
    replies = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    return proc, replies, (ingress.read_bytes() if ingress.exists() else b"")


def _frame(**message):
    message.setdefault("jsonrpc", "2.0")
    return (json.dumps(message) + "\n").encode()


def test_it_answers_initialize_with_a_negotiated_version(tmp_path):
    proc, replies, _ = _talk([_frame(id=1, method="initialize", params={
        "protocolVersion": "2025-06-18", "capabilities": {}})], tmp_path)
    assert proc.returncode == 0
    assert replies[0]["id"] == 1
    assert replies[0]["result"]["protocolVersion"] == "2025-06-18"
    assert "serverInfo" in replies[0]["result"]


def test_ping_is_answered_with_an_empty_result(tmp_path):
    _proc, replies, _ = _talk([_frame(id=2, method="ping")], tmp_path)
    assert replies[0] == {"jsonrpc": "2.0", "id": 2, "result": {}}


def test_a_tools_call_echoes_its_argument_back_as_content(tmp_path):
    """The echo is the point. A self test needs a server whose output it can
    predict exactly, so S1's byte equality check has something to compare."""
    _proc, replies, _ = _talk([_frame(id=3, method="tools/call", params={
        "name": "echo", "arguments": {"text": "round trip"}})], tmp_path)
    assert replies[0]["result"]["content"] == [
        {"type": "text", "text": "round trip"}]


def test_tools_list_offers_exactly_the_echo_tool(tmp_path):
    _proc, replies, _ = _talk([_frame(id=4, method="tools/list")], tmp_path)
    names = [tool["name"] for tool in replies[0]["result"]["tools"]]
    assert names == ["echo"]


def test_an_unknown_method_is_a_method_not_found_error(tmp_path):
    _proc, replies, _ = _talk([_frame(id=5, method="nope/nope")], tmp_path)
    assert replies[0]["error"]["code"] == -32601


def test_a_notification_is_not_answered(tmp_path):
    """A notification has no id, so answering it would invent one."""
    _proc, replies, _ = _talk([_frame(method="notifications/initialized"),
                               _frame(id=6, method="ping")], tmp_path)
    assert [r["id"] for r in replies] == [6]


# ── the instrument ───────────────────────────────────────────────────────

def test_every_received_byte_is_recorded_for_the_delivery_comparison(tmp_path):
    """The file the proxy cannot write. A test that asks the proxy whether it
    withheld something is asking the defendant, and this is the only reading
    taken on the far side of the thing being measured."""
    frames = [_frame(id=7, method="ping"),
              _frame(id=8, method="tools/call",
                     params={"name": "echo", "arguments": {"text": "seen"}})]
    _proc, _replies, ingress = _talk(frames, tmp_path)
    assert ingress == b"".join(frames)


def test_nothing_is_recorded_when_nothing_arrives(tmp_path):
    """The zero reading has to be a real zero, not an absent file that a test
    would read as one by default."""
    _proc, _replies, ingress = _talk([], tmp_path)
    assert ingress == b""


def test_it_writes_one_json_line_per_reply_and_nothing_else(tmp_path):
    """Anything else on stdout is a frame the client cannot parse, and a proxy
    between them would tear the session down for a protocol fault that was
    ours."""
    proc, _replies, _ = _talk([_frame(id=9, method="ping"),
                               _frame(id=10, method="ping")], tmp_path)
    lines = proc.stdout.splitlines()
    assert len(lines) == 2
    for line in lines:
        json.loads(line)


def test_the_instrument_records_what_arrived_not_what_parsed(tmp_path):
    """Found by mutation. An instrument that only counts well formed frames
    cannot see a malformed one leaking through, and a malformed frame reaching
    the server is exactly the leak a byte comparison exists to catch. What
    arrived is the measurement, whether or not it was JSON."""
    junk = b"{not json at all\n"
    blank = b"\n"
    _proc, _replies, ingress = _talk([junk, blank, _frame(id=11, method="ping")],
                                     tmp_path)
    assert junk in ingress
    assert ingress.startswith(junk + blank), \
        "a bare newline is a byte that arrived, and the comparison counts bytes"
