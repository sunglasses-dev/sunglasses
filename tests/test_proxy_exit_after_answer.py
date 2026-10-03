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


# ── an answer the caller's reader already holds in memory ─────────────────

# The kernel pipe is EMPTY once Python's BufferedReader has read ahead, so a
# reader that waits on the descriptor cannot see an answer it is already
# holding. `peek()` is the legal way a caller gets there.
_HOLD_THEN_ORPHAN = ("import subprocess,sys;w=sys.stdout.buffer.write;"
                     "w(sys.argv[1].encode()+b'\\n');sys.stdout.flush();"
                     "sys.stdin.buffer.read(1);"
                     "subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
                     "stdout=sys.stdout)")


def _prebuffered(child, wanted):
    """Make the caller's reader hold `wanted` in memory, kernel pipe empty."""
    import select
    assert child.stdout.peek(1)[:len(wanted)] == wanted
    assert not select.select([child.stdout.fileno()], [], [], 0)[0], (
        "the setup is wrong: the answer is still in the kernel pipe")


def test_an_answer_the_reader_already_holds_survives_the_exit():
    """The server wrote its answer, the caller peeked it into memory, then the
    server exits leaving a descendant holding the pipe. Only the exit is
    news on the descriptor, but the answer is in hand: it is delivered, and
    the session stays open because nothing is owed afterwards."""
    answer = _wire(_response(41))
    child = subprocess.Popen([sys.executable, "-c", _HOLD_THEN_ORPHAN,
                              answer.decode().rstrip("\n")],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    got, done = [], threading.Event()
    try:
        session = pump.Session()
        session.attach_upstream(child, pgid=child.pid)
        session.admit_request(41, method="tools/call", origin="client")
        _prebuffered(child, answer)

        def drive():
            try:
                got.extend(session.read_upstream(child.stdout))
            finally:
                done.set()

        threading.Thread(target=drive, daemon=True).start()
        deadline = time.monotonic() + 3
        while not got and time.monotonic() < deadline:
            time.sleep(0.02)
        child.stdin.write(b"x")
        child.stdin.flush()
        child.wait(timeout=5)                 # the leader is gone, a child holds the pipe
        time.sleep(1.5)                       # longer than the exit grace
        assert [f for f in got if f] == [answer], (
            "the answer the reader already held was lost", got,
            session.closed_with())
        assert session.closed_with() is None
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    assert done.wait(10), "stopping the group did not release the reader"
    child.wait(timeout=5)
    child.stdin.close()
    child.stdout.close()


def test_an_answer_the_reader_already_holds_is_delivered_without_any_exit():
    """The stall form of the same mistake: the server is alive and waiting for
    the next request, the answer is only in the reader's memory, and a reader
    that waits on the empty descriptor never delivers it."""
    answer = _wire(_response(41))
    child = subprocess.Popen([sys.executable, "-c",
                              "import sys,time;w=sys.stdout.buffer.write;"
                              "w(sys.argv[1].encode()+b'\\n');sys.stdout.flush();"
                              "time.sleep(30)", answer.decode().rstrip("\n")],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    got = []
    try:
        session = pump.Session()
        session.attach_upstream(child, pgid=child.pid)
        session.admit_request(41, method="tools/call", origin="client")
        _prebuffered(child, answer)
        threading.Thread(target=lambda: got.extend(
            session.read_upstream(child.stdout)), daemon=True).start()
        deadline = time.monotonic() + 3
        while not got and time.monotonic() < deadline:
            time.sleep(0.02)
        assert [f for f in got if f] == [answer], (
            "an answer sitting in the reader's memory was never delivered", got)
        assert session.closed_with() is None
        time.sleep(0.3)                  # the reader is waiting for the next frame
        assert os.get_blocking(child.stdout.fileno()), (
            "the look at what the reader already held left the pipe nonblocking")
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        time.sleep(0.2)
        child.wait(timeout=5)


def test_a_batch_longer_than_the_grace_still_gives_every_call_one_outcome():
    """Five answers written before the exit, 250 ms to scan each: more than
    the one second the watcher allows in total. Some are delivered and the
    rest are refused (the documented limit of the grace), but never twice,
    never unscanned, never out of order, and every call ends with exactly one
    outcome."""
    ids = [51, 52, 53, 54, 55]
    writer = ("import sys;w=sys.stdout.buffer.write;"
              "[w(a.encode()+b'\\n') for a in sys.argv[1:]];sys.stdout.flush()")
    child = _server(writer, *[json.dumps(_response(i)) for i in ids])

    def slower(raw, frame):
        time.sleep(0.25)
        return None

    try:
        session = pump.Session()
        session.attach_upstream(child, pgid=child.pid)
        for i in ids:
            session.admit_request(i, method="tools/call", origin="client")
        frames = _read_all(session, child, inspect=slower, timeout=20)
        delivered = [json.loads(f)["id"] for f in frames if f and b'"result"' in f]
        assert delivered == ids[:len(delivered)], delivered       # in order, once each
        refused = [i for i in ids[len(delivered):]
                   if session.answer_for(i, origin="client") is not None]
        assert len(delivered) + len(refused) == len(ids), (delivered, refused)
        if len(delivered) < len(ids):
            assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")
        else:
            assert session.closed_with() is None
    finally:
        _stop(child)


# ── the wrapper on its own: the order of its looks, with no process in the way

def _wrapper(source, fd, owed):
    """An `_ExitAwareSource` on a session that owes (or does not owe) one call."""
    session = pump.Session()
    if owed:
        session.admit_request(7, method="tools/call", origin="client")
    wake = pump._ExitWake()
    return session, wake, pump._ExitAwareSource(source, fd, wake, session)


def _read_once(src, n=100, within=3.0):
    """`src.read1(n)` on a thread: (finished, value). A wait that never ends
    shows up as not finished instead of hanging the run."""
    box = []
    t = threading.Thread(target=lambda: box.append(src.read1(n)), daemon=True)
    t.start()
    t.join(within)
    return (not t.is_alive()), (box[0] if box else None)


def test_the_wake_reaches_a_reader_that_has_nothing_to_read():
    """Empty pipe, the exit signalled, a call still owed: the reader must come
    back and judge. A look at the source that waits for bytes, or a signal
    that never reaches the pipe, leaves it parked until the watcher gives up."""
    r, w = os.pipe()
    source = os.fdopen(r, "rb")
    try:
        session, wake, src = _wrapper(source, r, owed=True)
        assert wake.signal()
        finished, value = _read_once(src)
        assert finished, "the reader never came back to judge the exit"
        assert value == b""
        assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")
    finally:
        os.close(w)
        source.close()


def test_bytes_that_land_after_the_look_still_beat_the_news_of_the_exit():
    """The look at what the source holds found nothing, then the server wrote,
    and the exit was signalled before the reader waited. Both descriptors are
    ready, and the bytes come first."""
    r, w = os.pipe()

    class LateWriter:
        looks = 0

        def read1(self, n):
            LateWriter.looks += 1
            return b"" if LateWriter.looks == 1 else os.read(r, n)

    try:
        session, wake, src = _wrapper(LateWriter(), r, owed=True)
        os.write(w, b"hello\n")
        assert wake.signal()
        finished, value = _read_once(src)
        assert finished and value == b"hello\n", (finished, value)
        assert session.closed_with() is None
    finally:
        os.close(w)
        os.close(r)


def test_bytes_the_source_holds_are_still_read_after_an_exit_was_judged():
    """Nothing owed, so the exit is judged and passes. Whatever the source
    holds after that is still the reader's to take before it waits again."""
    r, w = os.pipe()

    class HoldsLater:
        looks = 0

        def read1(self, n):
            HoldsLater.looks += 1
            return b"" if HoldsLater.looks == 1 else b"late\n"

    try:
        session, wake, src = _wrapper(HoldsLater(), r, owed=False)
        assert wake.signal()
        finished, value = _read_once(src)
        assert finished and value == b"late\n", (finished, value)
        assert session.closed_with() is None
    finally:
        os.close(w)
        os.close(r)


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
