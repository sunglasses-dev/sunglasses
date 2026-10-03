"""An answer the server wrote before it exited is an answer, not a fault.

T7.R1 makes an upstream exit with calls still pending an S5 fault, and that is
right for a server that dies WITHOUT answering. It was also firing for a server
that answered and then exited (an echo server on stdin EOF, any one-shot tool):
the watcher woke on the exit while the answer was still being read or scanned,
saw the call still pending, and closed the session, so a clean, fully scanned
answer was replaced by MALFORMED_UPSTREAM. The window is about a millisecond
(the real scan of a small message takes 0.4 to 1 ms), which is why it showed up
as a rare CI flake on the two oldest interpreters and never on a fast one.

The exit is now judged by the reader, at the one point where the question has
an exact answer: nothing left in the pipe and about to wait. These tests slow
the inbound scan down on purpose, because a race that passes ninety-nine runs in
a hundred proves nothing, and each of them fails on the code before the change.
"""
import json
import os
import signal
import subprocess
import sys
import threading
import time

import pytest

pump = pytest.importorskip("sunglasses.proxy.pump",
                           reason="the pump is the slice being specified here")

SLOW = 0.3      # seconds the inbound scan takes; the real one takes about 1 ms


def _wire(body):
    return json.dumps(body, separators=(",", ":")).encode() + b"\n"


def _request(request_id):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "hi"}}}


def _response(request_id, text="ok"):
    return {"jsonrpc": "2.0", "id": request_id,
            "result": {"content": [{"type": "text", "text": text}]}}


def _slow_inspect(raw, frame):
    """The inbound scan seam, slow. None means the answer is clean."""
    time.sleep(SLOW)
    return None


def _server(code, *args):
    """A real child in its own process group, so the exit is a PROCESS fact."""
    return subprocess.Popen([sys.executable, "-c", code, *args],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            start_new_session=True)


def _read_all(session, child, inspect=_slow_inspect, timeout=10):
    """Drive the reader on a thread, so a hang is a failure and not a stall."""
    got, done = [], threading.Event()

    def drive():
        try:
            got.extend(session.read_upstream(child.stdout, inspect=inspect))
        finally:
            done.set()

    threading.Thread(target=drive, daemon=True).start()
    assert done.wait(timeout), "the reader never returned"
    return got


def _stop(child):
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    child.wait(timeout=5)
    child.stdout.close()


ANSWER_THEN_EXIT = ("import sys;sys.stdout.buffer.write(sys.argv[1].encode()+"
                    "b'\\n');sys.stdout.flush()")


def test_an_answer_written_before_the_exit_is_delivered_while_it_is_scanned():
    """The failing shape, deterministic. The server writes its answer and is
    gone long before the 300 ms scan of that answer finishes, so the watcher
    sees an exit with the call pending for the whole length of the scan."""
    child = _server(ANSWER_THEN_EXIT, json.dumps(_response(41)))
    try:
        session = pump.Session()
        session.attach_upstream(child, pgid=child.pid)
        session.admit_request(41, method="tools/call", origin="client")
        frames = _read_all(session, child)
        assert session.closed_with() is None, (
            "a clean answer was replaced by a fault because the server exited")
        assert [json.loads(f)["id"] for f in frames if f] == [41]
        assert b'"result"' in frames[0]
    finally:
        _stop(child)


def test_an_answer_still_in_the_pipe_when_the_server_exits_is_read_first():
    """Data wins over the news of an exit. The first answer is being scanned
    (300 ms) while the server writes a second one and exits, so the pipe holds
    bytes AND the exit has happened when the reader comes back. Judging the
    exit first would fail call 42 with its answer sitting unread."""
    writer = ("import sys,time;w=sys.stdout.buffer.write;f=sys.stdout.flush;"
              "w(sys.argv[1].encode()+b'\\n');f();time.sleep(0.1);"
              "w(sys.argv[2].encode()+b'\\n');f()")
    child = _server(writer, json.dumps(_response(41)), json.dumps(_response(42)))
    try:
        session = pump.Session()
        session.attach_upstream(child, pgid=child.pid)
        session.admit_request(41, method="tools/call", origin="client")
        session.admit_request(42, method="tools/call", origin="client")
        frames = _read_all(session, child)
        assert session.closed_with() is None
        assert [json.loads(f)["id"] for f in frames if f] == [41, 42]
    finally:
        _stop(child)


def test_an_exit_with_no_answer_is_still_a_fault():
    """The rule itself, unchanged: a server that dies owing the answer."""
    child = _server("pass")
    try:
        session = pump.Session()
        session.attach_upstream(child, pgid=child.pid)
        session.admit_request(41, method="tools/call", origin="client")
        _read_all(session, child)
        assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")
        assert session.answer_for(41, origin="client") is not None
    finally:
        _stop(child)


def test_a_half_written_answer_before_the_exit_is_still_a_fault():
    """Draining the pipe must not turn an unfinished frame into a delivery."""
    child = _server("import sys;sys.stdout.write('{\"jsonrpc\":\"2.0\",\"id\":41');"
                    "sys.stdout.flush()")
    try:
        session = pump.Session()
        session.attach_upstream(child, pgid=child.pid)
        session.admit_request(41, method="tools/call", origin="client")
        frames = _read_all(session, child)
        assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")
        assert not any(b'"result"' in f for f in frames)
    finally:
        _stop(child)


def test_the_answer_comes_first_and_the_call_still_owed_is_the_fault():
    """Two calls pending. The server answers the first, spawns a grandchild
    that keeps the pipe open, and exits. The first answer is delivered, and the
    second call, which nothing will ever answer, closes the session as soon as
    the pipe is empty: a grandchild holding the pipe open is not a reason to
    wait, which is the F21 shape the existing process-fact test pins."""
    leader = ("import subprocess,sys;"
              "sys.stdout.buffer.write(sys.argv[1].encode()+b'\\n');"
              "sys.stdout.flush();"
              "subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
              "stdout=sys.stdout)")
    child = _server(leader, json.dumps(_response(41)))
    try:
        session = pump.Session()
        session.attach_upstream(child, pgid=child.pid)
        session.admit_request(41, method="tools/call", origin="client")
        session.admit_request(42, method="tools/call", origin="client")
        frames = _read_all(session, child)
        assert [json.loads(f)["id"] for f in frames
                if f and b'"result"' in f] == [41]
        assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")
        assert session.answer_for(42, origin="client") is not None
    finally:
        _stop(child)


def test_an_exit_that_owes_nothing_leaves_the_reader_waiting_quietly():
    """The server answers everything and exits, but a grandchild still holds
    the pipe. Nothing is owed, so nothing is a fault: the session stays open
    and the reader keeps waiting on the pipe, without spinning on the news of
    the exit it has already judged."""
    leader = ("import subprocess,sys;"
              "sys.stdout.buffer.write(sys.argv[1].encode()+b'\\n');"
              "sys.stdout.flush();"
              "subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
              "stdout=sys.stdout)")
    child = _server(leader, json.dumps(_response(41)))
    got, done = [], threading.Event()
    try:
        session = pump.Session()
        session.attach_upstream(child, pgid=child.pid)
        session.admit_request(41, method="tools/call", origin="client")

        def drive():
            try:
                got.extend(session.read_upstream(child.stdout,
                                                 inspect=_slow_inspect))
            finally:
                done.set()

        threading.Thread(target=drive, daemon=True).start()
        deadline = time.monotonic() + 10
        while not got and time.monotonic() < deadline:
            time.sleep(0.05)
        assert got, "the answer was never delivered"
        time.sleep(0.2)                       # the exit has been judged by now
        cpu = time.process_time()
        assert not done.wait(0.6), "the reader stopped reading after the exit"
        assert time.process_time() - cpu < 0.3, "the reader is spinning"
        assert session.closed_with() is None
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    assert done.wait(10), "stopping the group did not release the reader"
    assert session.closed_with() is None
    # Closed only once the reader has let go of it.
    child.wait(timeout=5)
    child.stdout.close()


# ── the same thing through the real proxy, over real pipes ────────────────

_PRELUDE = r"""
import runpy, sys, time
from sunglasses.proxy import inspection
_delay = float(sys.argv[1])
sys.argv = ["sunglasses.proxy"] + sys.argv[2:]
_real = inspection.scan
def _slow(params, *, channel, **kw):
    if "api_response" in repr(channel):
        time.sleep(_delay)
    return _real(params, channel=channel, **kw)
inspection.scan = _slow
runpy.run_module("sunglasses.proxy", run_name="__main__")
"""


def _proxy(tmp_path, frames, delay):
    server = [sys.executable, "-m", "sunglasses.proxy.echo_server",
              "--ingress", str(tmp_path / "ingress.log"),
              "--proc", str(tmp_path / "proc.json")]
    # The delay rides in argv and applies to inbound scans only. The approval
    # run below has none and goes through the plain entry point.
    argv = ([sys.executable, "-c", _PRELUDE, str(delay)] if delay is not None
            else [sys.executable, "-m", "sunglasses.proxy"])
    return subprocess.run(
        argv + ["--state-root", str(tmp_path / "state"), "--"] + server,
        input=b"".join(frames), capture_output=True, timeout=60)


def test_a_one_shot_client_still_gets_its_answer_through_a_slow_scan(tmp_path):
    """Test 124 of tests/test_proxy_serve.py, with the 1 ms margin made 300 ms.

    The client closes stdin together with its request, the echo server exits on
    that EOF right after answering, and the inbound scan of the answer takes
    300 ms. Before the change this was MALFORMED_UPSTREAM and exit 1 every time.
    """
    from sunglasses.proxy import approvals

    listing = (json.dumps({"jsonrpc": "2.0", "id": 99, "method": "tools/list"})
               + "\n").encode()
    _proxy(tmp_path, [listing], delay=None)
    captures = sorted((tmp_path / "state" / "captures").glob("*.json"))
    assert captures, "the proxy captured nothing to approve"
    server_id, sha, _ = captures[-1].name.split(".")
    approvals.Store(tmp_path / "state",
                    server_id=server_id).approve(snapshot_sha256=sha,
                                                 viewed=True)

    call = _wire(_request(1))
    proc = _proxy(tmp_path, [call], delay=SLOW)
    replies = [json.loads(line) for line in proc.stdout.splitlines()
               if line.strip()]
    assert replies, f"no answer came back: {proc.stderr[:400]!r}"
    assert "result" in replies[0], replies[0]
    assert proc.returncode == 0, proc.stderr[-400:]
