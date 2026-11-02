"""A stop signal ends the session through the normal teardown.

The server runs in a process group of its own, so a signal that kills the proxy
never reaches it. With the default action SIGTERM and SIGHUP made the proxy
leave at once and the server kept running with nobody mediating it; SIGINT ran
the teardown but ended in a traceback. These tests use a real proxy and a real
server over real pipes: the client keeps its end open, signals the proxy, and
then looks at the SERVER (is the pid gone), not at what the proxy says about
itself. Two tests run `serve.main` in this process so that they can count how
often the teardown ran.
"""
import io
import json
import os
import random
import signal
import subprocess
import sys
import threading
import time

import pytest

pytest.importorskip("sunglasses.proxy.serve")

# A test allowance, not a runtime deadline. The teardown's own named waits add up
# to 9.5 s at most (see `_end_on_signals`: 0.25 s input close, 5 s reader, 0.25 s
# exit status, 2 s group after SIGTERM, 1 s after SIGKILL, 1 s final reap); the
# rest is room for a slow machine. Anything past this allowance is a hang, not a
# slow teardown.
TEARDOWN_BOUND_S = 12.0


def _pipe_capacity():
    """How many bytes a pipe on this machine takes before a write would block."""
    read_end, write_end = os.pipe()
    try:
        os.set_blocking(write_end, False)
        total = 0
        try:
            while True:
                total += os.write(write_end, b"x" * 4096)
        except BlockingIOError:
            return total
    finally:
        os.close(read_end)
        os.close(write_end)


def _deaf_frame():
    """One request, larger than a pipe takes, for a server that never reads."""
    rng = random.Random(7)
    words = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike".split()
    title = " ".join(rng.choice(words) + str(rng.randrange(10 ** 6)) for _ in range(14000))
    frame = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "t", "version": "1", "title": title}}}) + "\n").encode()
    assert len(frame) > _pipe_capacity(), "the frame must not fit in the pipe"
    return frame


def _deaf_server(tmp_path):
    deaf = tmp_path / "deaf_server.py"
    deaf.write_text("import json, os, sys, time\n"
                    "open(sys.argv[1], 'w').write(json.dumps({'pid': os.getpid(), 'pgid': os.getpgid(0)}))\n"
                    "time.sleep(120)\n")
    return deaf


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A zombie still answers kill(0); its state says it is gone.
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            return handle.read().rsplit(b") ", 1)[1][:1] != b"Z"
    except OSError:
        pass
    try:
        out = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                             capture_output=True, text=True).stdout.strip()
        return bool(out) and not out.startswith("Z")
    except OSError:
        return True


def _start(tmp_path, *server_flags):
    proc_file = tmp_path / "proc.json"
    argv = [sys.executable, "-m", "sunglasses.proxy",
            "--state-root", str(tmp_path / "state"), "--",
            sys.executable, "-m", "sunglasses.proxy.echo_server",
            "--proc", str(proc_file), *server_flags]
    proxy = subprocess.Popen(argv, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc_file.exists():
            try:
                return proxy, json.loads(proc_file.read_text())
            except ValueError:
                pass
        if proxy.poll() is not None:
            break
        time.sleep(0.05)
    proxy.kill()
    pytest.fail("the proxy did not start its server")


def _wait(proxy):
    """Wait for the proxy WITHOUT closing its stdin. `communicate()` closes it,
    and a closed input starts the teardown on its own, so it would hide a
    missing signal handler.
    """
    proxy.wait(timeout=TEARDOWN_BOUND_S)
    return proxy.stderr.read()


def _stop(proxy, server):
    """Leave nothing behind whatever the test found."""
    for target in (lambda: proxy.kill(), lambda: os.killpg(server["pgid"], signal.SIGKILL)):
        try:
            target()
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        proxy.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        pass


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")
@pytest.mark.parametrize("name", ["SIGTERM", "SIGHUP", "SIGINT"])
def test_a_stop_signal_stops_the_server_and_the_proxy_leaves_by_its_own_code(tmp_path, name):
    signum = getattr(signal, name)
    proxy, server = _start(tmp_path)
    try:
        assert _alive(server["pid"])
        started = time.monotonic()
        proxy.send_signal(signum)
        err = _wait(proxy)
        took = time.monotonic() - started
        assert proxy.returncode == 128 + signum, err.decode("utf-8", "replace")
        assert not _alive(server["pid"]), "the server outlived the proxy"
        text = err.decode("utf-8", "replace")
        assert f"stopped by {name}" in text and "Traceback" not in text
        assert text.count("\n") == 1, text
        assert took < TEARDOWN_BOUND_S
    finally:
        _stop(proxy, server)


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")
def test_a_server_that_ignores_its_closed_input_is_still_stopped_by_a_signal(tmp_path):
    proxy, server = _start(tmp_path, "--linger")
    try:
        started = time.monotonic()
        proxy.send_signal(signal.SIGTERM)
        _wait(proxy)
        assert time.monotonic() - started < TEARDOWN_BOUND_S
        assert proxy.returncode == 128 + signal.SIGTERM
        assert not _alive(server["pid"]), "a lingering server outlived the proxy"
    finally:
        _stop(proxy, server)


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")
def test_a_second_signal_does_not_cut_the_teardown_short(tmp_path):
    """The teardown runs once. A supervisor that repeats SIGTERM must not turn
    the first one's bounded teardown into an abrupt exit that leaves the server."""
    proxy, server = _start(tmp_path, "--linger")
    try:
        proxy.send_signal(signal.SIGTERM)
        time.sleep(0.3)
        proxy.send_signal(signal.SIGTERM)
        proxy.send_signal(signal.SIGINT)
        _wait(proxy)
        assert proxy.returncode == 128 + signal.SIGTERM
        assert not _alive(server["pid"])
    finally:
        _stop(proxy, server)


def test_handlers_are_put_back_and_a_worker_thread_installs_none():
    from sunglasses.proxy import serve

    before = {s: signal.getsignal(s) for s in serve._END_SIGNALS}
    state = {"signum": None, "server_stopped": None}
    restore = serve._end_on_signals(state)
    assert all(signal.getsignal(s) is not before[s] for s in serve._END_SIGNALS)
    restore()
    assert {s: signal.getsignal(s) for s in serve._END_SIGNALS} == before

    seen = []

    def in_thread():
        seen.append(serve._end_on_signals({"signum": None}))
    worker = threading.Thread(target=in_thread)
    worker.start()
    worker.join()
    assert seen and {s: signal.getsignal(s) for s in serve._END_SIGNALS} == before


def test_the_handler_remembers_the_first_signal_and_takes_no_lock(monkeypatch):
    """A second signal can run the handler again while the main thread is inside
    a lock. A handler that sets an Event waits on that lock for itself and the
    teardown never finishes, so the handler may do nothing but assign."""
    from sunglasses.proxy import serve

    def boom(self):
        raise AssertionError("the signal handler must not touch an Event")
    monkeypatch.setattr(threading.Event, "set", boom)
    state = {"signum": None, "server_stopped": None}
    restore = serve._end_on_signals(state)
    try:
        signal.raise_signal(signal.SIGTERM)
        signal.raise_signal(signal.SIGINT)
    finally:
        restore()
    assert state["signum"] == signal.SIGTERM


def _run_main_in_process(tmp_path, signals_at, *server_flags, deaf=False):
    """`serve.main` on this thread over a real pipe and a real server, with the
    stop signals sent from a helper thread. Counts the teardown's steps."""
    from sunglasses.proxy import serve

    counts = {"stop_group": 0, "ending": 0, "handlers_back": None}
    real_stop, real_ending = serve.supervisor.stop_group, serve._record_ending

    def counting_stop(*args, **kwargs):
        counts["stop_group"] += 1
        return real_stop(*args, **kwargs)

    def counting_ending(*args, **kwargs):
        counts["ending"] += 1
        return real_ending(*args, **kwargs)

    read_end, write_end = os.pipe()
    stdin = os.fdopen(read_end, "rb")
    stderr = io.StringIO()
    proc_file = tmp_path / "proc.json"
    argv = ["--state-root", str(tmp_path / "state"), "--",
            sys.executable, "-m", "sunglasses.proxy.echo_server", "--proc", str(proc_file), *server_flags]
    if deaf:
        # A server that never reads, and a request too big for the pipe to it:
        # the client thread blocks writing it while holding the writer's lock.
        argv = ["--state-root", str(tmp_path / "state"), "--",
                sys.executable, str(_deaf_server(tmp_path)), str(proc_file)]

    closed_write = {"done": False}

    def send():
        deadline = time.monotonic() + 30
        while not proc_file.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        if deaf:
            os.write(write_end, _deaf_frame())
            time.sleep(1.0)
        for name, delay in signals_at:
            time.sleep(delay)
            if name == "EOF":
                closed_write["done"] = True
                os.close(write_end)
            else:
                os.kill(os.getpid(), getattr(signal, name))

    # A signal that lands after `main` has put its handlers back must not reach
    # pytest's own handler, so these stand in as the "previous" ones.
    ours = [each for each in serve._END_SIGNALS]
    standins = {each: (lambda *_: None) for each in ours}
    saved = {each: signal.signal(each, standins[each]) for each in ours}
    serve.supervisor.stop_group, serve._record_ending = counting_stop, counting_ending
    sender = threading.Thread(target=send, daemon=True)
    try:
        sender.start()
        code = serve.main(argv, stdin=stdin, stdout=io.BytesIO(), stderr=stderr)
        counts["handlers_back"] = all(
            signal.getsignal(each) is standins[each] for each in ours)
    finally:
        serve.supervisor.stop_group, serve._record_ending = real_stop, real_ending
        sender.join(timeout=10)
        for each, old in saved.items():
            signal.signal(each, old)
        # The write end goes first: the proxy's input-reader thread may still sit
        # in a read on `stdin`, and closing a buffered reader waits for that read.
        if not closed_write["done"]:
            closed_write["done"] = True
            try:
                os.close(write_end)
            except OSError:
                pass
        try:
            stdin.close()
        except OSError:
            pass
    server = json.loads(proc_file.read_text()) if proc_file.exists() else {}
    return code, counts, stderr.getvalue(), server


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")
def test_repeated_signals_run_the_teardown_once(tmp_path):
    code, counts, err, server = _run_main_in_process(
        tmp_path, [("SIGTERM", 0.3), ("SIGHUP", 0.3), ("SIGINT", 0.3)], "--linger")
    assert code == 128 + signal.SIGTERM, err
    assert counts == {"stop_group": 1, "ending": 1, "handlers_back": True}, counts
    assert err.count("\n") == 1 and "stopped by SIGTERM" in err, err
    assert server and not _alive(server["pid"])


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")
def test_a_signal_during_the_teardown_that_a_closed_input_began_runs_it_once(tmp_path):
    code, counts, err, server = _run_main_in_process(
        tmp_path, [("EOF", 0.3), ("SIGTERM", 0.3), ("SIGHUP", 0.3)], "--linger")
    assert counts == {"stop_group": 1, "ending": 1, "handlers_back": True}, counts
    assert err.count("\n") <= 1, err
    assert server and not _alive(server["pid"])
    if "stopped by" in err:
        assert code == 128 + signal.SIGTERM


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")
def test_a_server_that_stopped_reading_does_not_hold_the_teardown_up(tmp_path):
    """A frame the proxy accepted and the server never reads fills the pipe, so
    the client thread blocks flushing it while holding the writer's lock. The
    teardown must still stop the server's group, not wait for that lock."""
    deaf = _deaf_server(tmp_path)
    proc_file = tmp_path / "deaf.json"
    frame = _deaf_frame()
    proxy = subprocess.Popen(
        [sys.executable, "-m", "sunglasses.proxy", "--state-root", str(tmp_path / "state"), "--",
         sys.executable, str(deaf), str(proc_file)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 30
    server = None
    while time.monotonic() < deadline and server is None:
        try:
            server = json.loads(proc_file.read_text())
        except (OSError, ValueError):
            time.sleep(0.05)
    assert server, "the server did not start"
    try:
        proxy.stdin.write(frame)
        proxy.stdin.flush()
        time.sleep(1.5)
        proxy.send_signal(signal.SIGTERM)
        err = _wait(proxy)
        assert proxy.returncode == 128 + signal.SIGTERM, err.decode("utf-8", "replace")
        assert not _alive(server["pid"]), "the server outlived the proxy"
    finally:
        _stop(proxy, server)


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")
def test_a_signal_while_input_is_blocked_stops_the_server_once_and_ends_once(tmp_path):
    """The server dies when the teardown stops its group, and the session sees
    that end of output with a request pending. Stopping the group again from
    there is a second owner of the same stop."""
    code, counts, err, server = _run_main_in_process(
        tmp_path, [("SIGTERM", 0.2)], deaf=True)
    time.sleep(1.0)   # a second stop, if any, comes from the session after the first
    assert code == 128 + signal.SIGTERM, err
    assert counts == {"stop_group": 1, "ending": 1, "handlers_back": True}, counts
    assert server and not _alive(server["pid"])


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")
def test_a_helper_thread_that_cannot_start_still_runs_the_ending_and_the_stop(tmp_path, monkeypatch):
    """Closing the server's input is a courtesy. If no thread can be started for
    it, the ending is still written and the server's group is still stopped."""
    real_start = threading.Thread.start

    def start(self):
        if getattr(self._target, "__name__", "") == "close":
            raise RuntimeError("can't start new thread")
        return real_start(self)
    monkeypatch.setattr(threading.Thread, "start", start)
    code, counts, err, server = _run_main_in_process(
        tmp_path, [("SIGTERM", 0.3)], "--linger")
    assert code == 128 + signal.SIGTERM, err
    assert counts == {"stop_group": 1, "ending": 1, "handlers_back": True}, counts
    assert "Traceback" not in err, err
    assert server and not _alive(server["pid"])


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")
def test_a_session_that_closed_itself_first_is_not_stopped_a_second_time(tmp_path, monkeypatch):
    """A request the server never answers ends the session on its deadline, and
    that close stops the server's group. The teardown that follows finds the
    group gone and does not stop it again. A slow machine reaches this order
    before any signal arrives."""
    from sunglasses.proxy import serve

    monkeypatch.setitem(serve.bounds.DEADLINES, "upstream_response", 300)
    code, counts, err, server = _run_main_in_process(
        tmp_path, [("SIGTERM", 0.2)], deaf=True)
    assert counts["stop_group"] == 1 and counts["ending"] == 1, counts
    assert code == serve.EXIT_FAULT, (code, err)
    assert server and not _alive(server["pid"])


def test_two_callers_that_ask_to_stop_a_group_at_once_stop_it_once():
    """The claim is decided under one lock, so a stop that is still in flight
    cannot be mistaken for no stop at all."""
    from sunglasses.proxy import supervisor

    claim = supervisor.StopOnce()
    calls, started, release = [], threading.Event(), threading.Event()

    def slow_stop():
        calls.append(1)
        started.set()
        release.wait(5)
        return True
    answers = {}

    def first():
        answers["first"] = claim.run(slow_stop)
    winner = threading.Thread(target=first)
    winner.start()
    assert started.wait(5)

    def second():
        answers["second"] = claim.run(lambda: calls.append(2) or True)
    loser = threading.Thread(target=second)
    loser.start()
    time.sleep(0.2)
    assert loser.is_alive(), "the second caller must wait for the stop in flight"
    release.set()
    winner.join(5)
    loser.join(5)
    assert calls == [1] and answers == {"first": True, "second": True}, (calls, answers)
    assert claim.run(lambda: calls.append(3) or True) is True and calls == [1], calls


def test_a_stop_that_did_not_end_with_the_group_gone_can_be_tried_again():
    from sunglasses.proxy import supervisor

    claim = supervisor.StopOnce()
    assert claim.run(lambda: False) is False
    assert claim.run(lambda: True) is True


def test_a_caller_that_waits_for_a_stop_that_never_finishes_gives_up(monkeypatch):
    from sunglasses.proxy import supervisor

    monkeypatch.setattr(supervisor, "STOP_WAIT_S", 0.3)
    claim = supervisor.StopOnce()
    started, release = threading.Event(), threading.Event()
    winner = threading.Thread(
        target=lambda: claim.run(lambda: (started.set(), release.wait(5), True)[2]))
    winner.start()
    assert started.wait(5)
    began = time.monotonic()
    assert claim.run(lambda: True) is False
    assert 0.25 < time.monotonic() - began < 2.0
    release.set()
    winner.join(5)
