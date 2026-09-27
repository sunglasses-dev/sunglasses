"""A reader that dies closes the session BY NAME (T9 ruling R69, 0.6.1).

serve.py runs the two directions as threads, `_drain` for the upstream and
`_drain_client` for the client, and both ended in `except Exception: pass`. So
an exception out of the Route ended the thread, `done` was set, and the main
thread tore the session down as if it had ended cleanly: SESSION_TORN_DOWN
with reason_code null and rule null, exit status 0, and a client whose request
had been read and forwarded never answered (T8 probe 2026-09-25 at b276d38f,
both readers).

The ruling. Each drain closes the session with SCAN_EXCEPTION under S3 and one
cause kind, READER_FAILED, shared by both because it is one fault. The detail
names the exception CLASS and never its message, since the message can carry
peer bytes. Ids read before the close are answered (R66), nothing is forwarded
after it, and the process exits nonzero.

T9 ruling 70. Only an ADMITTED id is owed a refusal. A frame that raises
before admission has an "id" the parser never finished trusting, so answering
it would branch on a value the attacker wrote; that frame gets the named close
instead, said to the client on the wire as the null id error before its pipe
ends. A raise after admission is an admitted id and R66 refuses it.

The unit rows drive each drain with a stub; the wire rows run the real entry
over real pipes with one Route method replaced so it raises once.
"""
import io
import json
import os
import pathlib
import subprocess
import sys
import threading
import types

import pytest

from sunglasses.proxy import pump, serve

# The exception's message. It must reach no client frame, no stderr line and
# no receipt row: only the class name is allowed out.
SENTINEL = "peer-text-that-must-not-leave-7f3a"


class _Spy:
    """Records every `_close` call on a real session and lets it through."""

    def __init__(self, session):
        self.calls = []
        real = session._close

        def close(reason, detail, rule="S5", budget=None, *, kind=None):
            self.calls.append(dict(reason=reason, detail=detail, rule=rule,
                                   kind=kind))
            return real(reason, detail, rule=rule, budget=budget, kind=kind)

        session._close = close


def _assert_named_close(session, spy):
    assert session.closed_with() == ("SCAN_EXCEPTION", "S3"), session.closed_with()
    first = spy.calls[0]
    assert first["kind"] == "READER_FAILED", first
    assert "RuntimeError" in first["detail"], first
    assert SENTINEL not in first["detail"], first


# ── unit: each drain, driven with a stub ────────────────────────────────────

def test_the_upstream_reader_failing_closes_the_session_by_name():
    session = pump.Session()
    spy = _Spy(session)
    paid = []

    class Engine:
        def pump_upstream(self, stream):
            raise RuntimeError(SENTINEL)

        def pay_retained_refusals(self):
            paid.append(1)

    Engine.session = session
    done = threading.Event()
    serve._drain(Engine(), types.SimpleNamespace(stdout=io.BytesIO()), done)

    assert done.is_set()
    _assert_named_close(session, spy)
    # The reader that would have paid the retained debt on its way out is the
    # one that died, so the drain pays it.
    assert paid == [1]


def test_the_client_reader_failing_closes_the_session_by_name():
    session = pump.Session()
    spy = _Spy(session)
    seen = []
    announced = []

    class Engine:
        def client_frame(self, raw):
            seen.append(raw)
            raise RuntimeError(SENTINEL)

        def announce_close(self, reason, rule):
            announced.append((reason, rule, session.closed_with()))

    stream = io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
                        b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n')
    done = threading.Event()
    serve._drain_client(Engine(), session, stream, done)

    assert done.is_set()
    _assert_named_close(session, spy)
    assert len(seen) == 1, "the reader went on reading after its own failure"
    # Ruling 70 (a). The close is said to the client, and said while the
    # session is still open: after the close the process can be gone.
    assert announced == [("SCAN_EXCEPTION", "S3", None)], announced


def test_the_control_a_reader_that_ends_normally_closes_nothing():
    session = pump.Session()

    class Engine:
        def pump_upstream(self, stream):
            return None

        def client_frame(self, raw):
            return None

    Engine.session = session
    serve._drain(Engine(), types.SimpleNamespace(stdout=io.BytesIO()),
                 threading.Event())
    serve._drain_client(Engine(), session,
                        io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'),
                        threading.Event())
    assert session.closed_with() is None


# ── wire: the real entry, one Route method raising once ─────────────────────

WRAPPER = r'''
import json, sys
from sunglasses.proxy import route, serve
from sunglasses.proxy.commands import main
which, sentinel, argv = sys.argv[1], sys.argv[2], sys.argv[3:]
real = route.Route.client_frame
if which == "client":
    # Before admission: the Route never sees id 100.
    def client_frame(self, raw):
        if json.loads(raw).get("id") == 100:
            raise RuntimeError(sentinel)
        return real(self, raw)
    route.Route.client_frame = client_frame
elif which == "admitted":
    # After admission: id 100 is admitted, then the forward raises, so the id
    # is owed and was never sent.
    def client_frame(self, raw):
        if json.loads(raw).get("id") != 100:
            return real(self, raw)
        forward = self.upstream_write
        def refuse(*args, **kwargs):
            raise RuntimeError(sentinel)
        self.upstream_write = refuse
        try:
            return real(self, raw)
        finally:
            self.upstream_write = forward
    route.Route.client_frame = client_frame
else:
    def pump_upstream(self, stream):
        # The server's answer to the pending id is taken off the pipe and
        # never released: the id is owed, and only a payment answers it.
        stream.readline()
        raise RuntimeError(sentinel)
    route.Route.pump_upstream = pump_upstream
serve.exit_process(main(argv))
'''


def _frame(request_id, method="tools/list"):
    return (json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method})
            + "\n").encode()


def _run(which, tmp_path, frames, late=None):
    """Run the proxy with stdin held open, so the only way out is the session
    ending, and read every side afterwards. `late` is written once the first
    reply is back, which is after the close on the upstream row."""
    ingress = tmp_path / "ingress.log"
    server = [sys.executable, "-m", "sunglasses.proxy.echo_server",
              "--ingress", str(ingress), "--proc", str(tmp_path / "proc.json")]
    root = str(pathlib.Path(serve.__file__).resolve().parents[2])
    env = dict(os.environ, PYTHONPATH=root, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.Popen(
        [sys.executable, "-c", WRAPPER, which, SENTINEL,
         "--state-root", str(tmp_path / "state"), "--"] + server,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, bufsize=0)
    proc.stdin.write(b"".join(frames))
    proc.stdin.flush()
    lines = [proc.stdout.readline()]
    if late is not None:
        try:
            proc.stdin.write(late)
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
    try:
        rc = proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        pytest.fail(f"the {which} reader died and the proxy did not end")
    lines += proc.stdout.read().splitlines()
    err = proc.stderr.read()
    # Unbuffered, so a late write that met a closed pipe left nothing behind
    # for close to flush; the guard is for the pipe itself.
    try:
        proc.stdin.close()
    except (BrokenPipeError, OSError):
        pass
    replies = [json.loads(line) for line in lines if line.strip()]
    rows = [json.loads(line)
            for path in sorted((tmp_path / "state").rglob("*.jsonl"))
            for line in path.read_text().splitlines() if line.strip()]
    arrived = ingress.read_bytes() if ingress.exists() else b""
    return rc, replies, rows, arrived, err


def _torn_down(rows):
    torn = [(r.get("reason_code"), r.get("rule"))
            for r in rows if r.get("kind") == "SESSION_TORN_DOWN"]
    assert len(torn) == 1, torn
    return torn[0]


def _methods(arrived):
    """The methods of the frames the server received, from its own ingress
    log. Methods and not ids: the proxy puts its own id on the upstream side,
    so the client's id never reaches the server."""
    methods = []
    for line in arrived.splitlines():
        try:
            methods.append(json.loads(line).get("method"))
        except ValueError:
            methods.append("unparsed")
    return methods


def _answers(replies, request_id):
    return [r for r in replies if r.get("id") == request_id]


def _assert_close_said_on_the_wire(replies):
    """Ruling 70 (a). One error with the null id, naming the reason and the
    rule, in what the client read before its pipe ended. The class is not
    here: `envelope.withheld` drops every detail by design (T4.R7)."""
    closes = [r for r in replies if "id" in r and r["id"] is None and "error" in r]
    assert len(closes) == 1, replies
    data = closes[0]["error"].get("data", {})
    assert (data.get("reason_code"), data.get("rule")) \
        == ("SCAN_EXCEPTION", "S3"), closes


def _nothing_leaked(replies, rows, err):
    assert SENTINEL not in json.dumps(replies)
    assert SENTINEL not in json.dumps(rows)
    assert SENTINEL.encode() not in err, err[-300:]
    assert b"Traceback" not in err, err[-300:]


def test_the_upstream_reader_dying_is_a_named_fault_on_the_wire(tmp_path):
    rc, replies, rows, arrived, err = _run(
        "upstream", tmp_path, [_frame(99)], late=_frame(101, "ping"))

    assert _methods(arrived) == ["tools/list"], arrived  # stimulus: 99 forwarded
    assert _torn_down(rows) == ("SCAN_EXCEPTION", "S3")
    assert rc != 0, rc
    # R66. The id was read and forwarded before the close, so it is answered,
    # once, and the answer says why.
    owed = _answers(replies, 99)
    assert len(owed) == 1, replies
    assert owed[0].get("error", {}).get("data", {}).get("reason_code") \
        == "SCAN_EXCEPTION", owed
    # Nothing crosses after the close.
    assert _methods(arrived) == ["tools/list"], arrived
    assert not _answers(replies, 101), replies
    _nothing_leaked(replies, rows, err)


def test_the_client_reader_dying_is_a_named_fault_on_the_wire(tmp_path):
    rc, replies, rows, arrived, err = _run(
        "client", tmp_path,
        [_frame(99), _frame(100, "ping"), _frame(101, "ping")])

    assert _torn_down(rows) == ("SCAN_EXCEPTION", "S3")
    assert rc != 0, rc
    # R66. Id 99 was read before the close: one answer, whichever party
    # delivered it.
    assert len(_answers(replies, 99)) == 1, replies
    # Ruling 70. Id 100 raised before admission: no per-id refusal, and the
    # close names the cause to the client instead.
    assert not _answers(replies, 100), replies
    _assert_close_said_on_the_wire(replies)
    # The failing frame and everything after it stay on this side.
    assert _methods(arrived) == ["tools/list"], arrived
    assert not _answers(replies, 101), replies
    _nothing_leaked(replies, rows, err)


def test_a_raise_after_admission_is_refused_by_its_id_on_the_wire(tmp_path):
    """Ruling 70 (b). An admitted id is owed, so R66 refuses it by its id, as
    it did before the ruling."""
    rc, replies, rows, arrived, err = _run(
        "admitted", tmp_path,
        [_frame(99), _frame(100, "ping"), _frame(101, "ping")])

    assert _torn_down(rows) == ("SCAN_EXCEPTION", "S3")
    assert rc != 0, rc
    assert _methods(arrived) == ["tools/list"], arrived  # stimulus: 100 never sent
    owed = _answers(replies, 100)
    assert len(owed) == 1, replies
    assert owed[0].get("error", {}).get("data", {}).get("reason_code") \
        == "SCAN_EXCEPTION", owed
    assert len(_answers(replies, 99)) == 1, replies
    assert not _answers(replies, 101), replies
    _nothing_leaked(replies, rows, err)


def test_the_control_with_no_reader_failing_the_session_ends_clean(tmp_path):
    """The same harness, no method replaced: the stimulus is the raise and
    nothing else about the run."""
    ingress = tmp_path / "ingress.log"
    server = [sys.executable, "-m", "sunglasses.proxy.echo_server",
              "--ingress", str(ingress), "--proc", str(tmp_path / "proc.json")]
    proc = subprocess.run(
        [sys.executable, "-m", "sunglasses.proxy",
         "--state-root", str(tmp_path / "state"), "--"] + server,
        input=_frame(99), capture_output=True, timeout=60)
    rows = [json.loads(line)
            for path in sorted((tmp_path / "state").rglob("*.jsonl"))
            for line in path.read_text().splitlines() if line.strip()]
    assert _torn_down(rows) == (None, None)
    assert proc.returncode == 0, proc.stderr[-300:]
