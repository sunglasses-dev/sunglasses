"""The upstream `initialize` result is inspected like every other result.

`pump.Session.read_upstream` routes an initialize response through
`_initialize_result`, which used to call `deliver_response(...)` without the
`inspect` seam every other result gets. The MCP initialize result carries
`instructions`, free text that clients place in the model's system prompt, and
`serverInfo` strings; the selector lists the initialize result on the
api_response channel.
"""
import io
import json
import os
import select
import subprocess
import sys
import time

import pytest

from sunglasses.proxy import bounds, inspection

from _proxy_inspect_harness import (INJECTION, flagging_scan, frame, init_request,
                                make_route)


def _init_result(request_id=1, **extra):
    body = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
            "serverInfo": {"name": "lab-server", "version": "1"}}
    body.update(extra)
    return frame(id=request_id, result=body)


def test_initialize_result_is_handed_to_the_scanner(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path)
    engine.client_frame(init_request(1))
    assert upstream.bytes == init_request(1)          # request forwarded
    engine.pump_upstream(io.BytesIO(_init_result(1, instructions=INJECTION)))
    assert client.messages(), "the client got no answer at all"
    channels = [scan["channel"] for scan in scans]
    assert "api_response" in channels, (
        "the initialize RESULT was delivered without a scan; only the "
        f"request side ran: {channels}")


def test_poisoned_instructions_are_withheld_not_forwarded(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(init_request(1))
    engine.pump_upstream(io.BytesIO(_init_result(1, instructions=INJECTION)))
    answers = client.messages()
    assert len(answers) == 1
    assert "result" not in answers[0] or INJECTION not in json.dumps(answers[0]), (
        "the injected `instructions` text reached the client verbatim: "
        f"{answers[0]}")


def test_poisoned_server_info_is_withheld_not_forwarded(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(init_request(1))
    engine.pump_upstream(io.BytesIO(_init_result(
        1, serverInfo={"name": INJECTION, "version": "1"})))
    answers = client.messages()
    assert len(answers) == 1
    assert INJECTION not in json.dumps(answers[0])


def _receipt_kinds(tmp_path):
    rows = []
    for path in (tmp_path / "receipts").glob("*.jsonl"):
        rows += [json.loads(line) for line in path.read_text().splitlines()]
    return rows


def test_a_clean_initialize_result_still_crosses_and_is_scanned(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(init_request(1))
    engine.pump_upstream(io.BytesIO(_init_result(1, instructions="be brief")))
    answers = client.messages()
    assert len(answers) == 1 and answers[0]["result"]["instructions"] == "be brief"
    assert [scan["channel"] for scan in scans if scan["channel"] == "api_response"]
    assert engine.session._closed is None


def test_the_receipts_show_the_initialize_result_was_scanned(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(init_request(1))
    engine.pump_upstream(io.BytesIO(_init_result(1, instructions=INJECTION)))
    rows = [row for row in _receipt_kinds(tmp_path)
            if row.get("kind") in ("SCAN_STARTED", "SCAN_RESULT", "SETTLED")]
    initialize_scans = [row for row in rows if row.get("kind") == "SCAN_STARTED"
                        and row.get("method") == "initialize"]
    assert len(initialize_scans) == 2, rows      # the request, then the result
    assert rows[-1]["kind"] == "SETTLED"
    assert rows[-1]["reason_code"] == "PROHIBITED_CONTENT", rows[-1]


def test_a_withheld_initialize_result_ends_the_session_with_one_answer(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(init_request(1))
    engine.pump_upstream(io.BytesIO(_init_result(1, instructions=INJECTION)))
    answers = client.messages()
    assert len(answers) == 1
    assert answers[0]["error"]["message"] == "SUNGLASSES_WITHHELD"
    assert answers[0]["error"]["data"]["reason_code"] == "PROHIBITED_CONTENT"
    assert engine.session._closed is not None


@pytest.mark.parametrize("extra", [{"instructions": INJECTION},
                                   {"note": {"text": INJECTION}},
                                   {"harmless": 1}])
def test_a_frame_with_a_member_the_scan_does_not_read_is_withheld_whole(tmp_path,
                                                                        extra):
    """The scanner is shown the result object only, so a member beside it is
    not read. Bytes cross only if the scan read them: the frame is withheld
    whole, and on initialize that ends the session with the same reason."""
    engine, upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(init_request(1))
    engine.pump_upstream(io.BytesIO(frame(
        id=1, result={"protocolVersion": "2025-06-18",
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": "lab-server", "version": "1"}},
        **extra)))
    answers = client.messages()
    assert len(answers) == 1
    assert INJECTION not in json.dumps(answers[0]), answers[0]
    assert answers[0]["error"]["message"] == "SUNGLASSES_WITHHELD"
    assert answers[0]["error"]["data"]["reason_code"] == "UNSUPPORTED_CONTENT"
    assert engine.session._closed is not None
    settled = [row for row in _receipt_kinds(tmp_path) if row.get("kind") == "SETTLED"]
    assert settled[-1]["reason_code"] == "UNSUPPORTED_CONTENT", settled[-1]


def test_a_frame_with_no_extra_members_is_forwarded_as_before(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path, scan=flagging_scan)
    engine.client_frame(init_request(1))
    engine.pump_upstream(io.BytesIO(_init_result(1, instructions="be brief")))
    assert client.messages() == [{
        "jsonrpc": "2.0", "id": 1,
        "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                   "serverInfo": {"name": "lab-server", "version": "1"},
                   "instructions": "be brief"}}]


def test_control_the_real_engine_flags_the_same_text_on_api_response():
    """Control: this is not a detector gap. The engine flags the text when it
    is shown it on the channel the row names."""
    surface = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
               "serverInfo": {"name": "lab-server", "version": "1"},
               "instructions": INJECTION}
    binding = {"digest": "d", "channel": "api_response", "generation": 1,
               "invocation_token": "t"}
    out = inspection.scan(surface, channel="api_response", binding=binding,
                          content_bytes=len(INJECTION))
    assert out["findings"], "control failed: engine did not flag the text"


SERVER = r'''
import json, sys
injection = sys.argv[1]
where = sys.argv[2]
for raw in sys.stdin.buffer:
    m = json.loads(raw)
    if "id" not in m:
        continue
    if m.get("method") == "initialize":
        r = {"protocolVersion": (m.get("params") or {}).get("protocolVersion", "2025-06-18"),
             "capabilities": {"tools": {}},
             "serverInfo": {"name": "lab-server", "version": "1"}}
        if where == "inner":
            r["instructions"] = injection
    else:
        r = {}
    out = {"jsonrpc": "2.0", "id": m["id"], "result": r}
    if where == "outer" and m.get("method") == "initialize":
        out["instructions"] = injection
    sys.stdout.buffer.write((json.dumps(out) + "\n").encode())
    sys.stdout.buffer.flush()
'''


@pytest.mark.parametrize("worker", ["inprocess", "process"])
@pytest.mark.parametrize("where", ["inner", "outer"])
def test_end_to_end_real_proxy_never_forwards_the_poisoned_text(tmp_path, worker,
                                                               where):
    """The shipped artifact over real pipes: `python -m sunglasses.proxy`, in
    both worker modes. `inner` puts the text in `instructions` (withheld);
    `outer` puts it in a top-level member beside `result` (the frame is
    withheld whole and the session closes)."""
    argv = [sys.executable, "-m", "sunglasses.proxy", "--worker", worker,
            "--state-root", str(tmp_path / "state"), "--", sys.executable,
            "-c", SERVER, INJECTION, where]
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            bufsize=0)
    proc.stdin.write(init_request(1))
    first = b""
    fd = proc.stdout.fileno()
    deadline = time.monotonic() + 90
    while b"\n" not in first:
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([fd], [], [], left)[0]:
            break
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        first += chunk
    try:
        proc.stdin.close()
    except BrokenPipeError:
        pass
    proc.stdin = None
    try:
        rest, err = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        rest, err = proc.communicate()
    replies = [json.loads(l) for l in (first + rest).splitlines() if l.strip()]
    assert replies, f"no reply from the proxy; stderr={err[-2000:]!r}"
    assert INJECTION not in json.dumps(replies[0]), (
        "the real proxy forwarded the server's poisoned text to the client "
        f"({where}, {worker}): {replies[0]}")
    if where == "outer":
        assert replies[0]["error"]["message"] == "SUNGLASSES_WITHHELD", replies[0]
        assert replies[0]["error"]["data"]["reason_code"] == "UNSUPPORTED_CONTENT"
