"""A stop signal ends the session through the normal teardown.

The server runs in a process group of its own, so a signal that kills the proxy
never reaches it. With the default action SIGTERM and SIGHUP made the proxy
leave at once and the server kept running with nobody mediating it, and SIGINT
ended in a traceback. Only a closed input ran the designed teardown. These tests
use a real proxy and a real server over real pipes: the client keeps its end
open, signals the proxy, and then looks at the SERVER (is the pid gone), not at
what the proxy says about itself.
"""
import json
import os
import signal
import subprocess
import sys
import time

import pytest

pytest.importorskip("sunglasses.proxy.serve")

# The teardown bound for a server that ignores the closed input: the proxy
# waits up to 5 s for its reader, then supervisor.stop_group gives 2 s before
# SIGKILL. Anything past this is a hang, not a slow teardown.
TEARDOWN_BOUND_S = 12.0


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
    and a closed input is the one thing that already ran the teardown, so it
    would hide a missing signal handler."""
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
    import threading

    before = {s: signal.getsignal(s) for s in serve._END_SIGNALS}
    done, state = threading.Event(), {"signum": None, "server_stopped": None}
    restore = serve._end_on_signals(done, state)
    assert all(signal.getsignal(s) is not before[s] for s in serve._END_SIGNALS)
    restore()
    assert {s: signal.getsignal(s) for s in serve._END_SIGNALS} == before

    seen = []

    def in_thread():
        seen.append(serve._end_on_signals(threading.Event(), {"signum": None}))
    worker = threading.Thread(target=in_thread)
    worker.start()
    worker.join()
    assert seen and {s: signal.getsignal(s) for s in serve._END_SIGNALS} == before
