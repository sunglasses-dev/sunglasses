"""Two setups of a Ctrl-C that lands while `sunglasses proxy` is serving, and one ordering check.

The subprocess tests use a real proxy, a real server and real pipes. SIGINT goes to the proxy; what is
read afterwards is the proxy's exit status and stderr, and whether the SERVER's pid is still there, not
what the proxy says about itself. Without the `except KeyboardInterrupt` in `serve.main` the teardown
still runs, but `main` raises instead of returning, so `exit_process` never takes its `os._exit` branch
and the interpreter aborts on the client reader blocked on stdin.

The in-process test pins the order inside `main`: the interrupted status is set before the session is
marked finished. These tests pin the handled case only; a Ctrl-C that lands elsewhere is not tested here.
"""
import json
import os
import threading
import io
import signal
import subprocess
import sys
import time

import pytest

from sunglasses.proxy import serve

pytest.importorskip("fcntl", reason="the proxy supervisor needs process groups")


def _gone(pid, within=5.0):
    end = time.monotonic() + within
    while time.monotonic() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


@pytest.mark.parametrize("linger", [False, True], ids=["server-exits-on-closed-input", "server-ignores-closed-input"])
def test_sigint_exits_130_without_an_abort_and_the_server_is_gone(tmp_path, linger):
    proc_file = tmp_path / "proc.json"
    server = [sys.executable, "-m", "sunglasses.proxy.echo_server", "--proc", str(proc_file)]
    if linger:
        server.append("--linger")
    proxy = subprocess.Popen(
        [sys.executable, "-m", "sunglasses.proxy", "--state-root", str(tmp_path / "state"), "--"] + server,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    info = None
    try:
        end = time.monotonic() + 30
        while time.monotonic() < end:
            if proc_file.exists() and proc_file.read_text().strip().endswith("}"):
                info = json.loads(proc_file.read_text())
                break
            time.sleep(0.05)
        assert info is not None, "the server never started"
        proxy.send_signal(signal.SIGINT)
        try:
            code = proxy.wait(timeout=30)
        except subprocess.TimeoutExpired:
            pytest.fail("the proxy did not exit within 30 s of SIGINT")
        err = proxy.stderr.read().decode("utf-8", "replace")
        assert code == 130, (code, err[-600:])
        assert "Fatal Python error" not in err, err[-600:]
        assert "Traceback" not in err, err[-600:]
        assert _gone(info["pid"]), "the server is still running"
    finally:
        if proxy.poll() is None:
            proxy.kill()
        for stream in (proxy.stdin, proxy.stdout, proxy.stderr):
            try:
                stream.close()
            except Exception:
                pass
        if info is not None:
            try:
                os.killpg(info["pgid"], signal.SIGKILL)
            except Exception:
                pass


def test_the_interrupted_status_is_set_before_the_session_is_marked_finished(tmp_path, monkeypatch):
    """The status has to be 130 before the session is marked finished: this test reads the caller's
    `code` at the moment the marker is set. Marking the session finished does not end the process;
    `exit_process` runs after `main` returns."""
    seen = []

    class Marker(threading.Event):
        def set(self):
            seen.append(sys._getframe(1).f_locals.get("code"))
            super().set()

    monkeypatch.setattr(serve, "_FINISHED", Marker())
    proc_file = tmp_path / "proc.json"
    read_end, write_end = os.pipe()

    def interrupt_when_serving():
        end = time.monotonic() + 30
        while time.monotonic() < end:
            if proc_file.exists() and proc_file.read_text().strip().endswith("}"):
                break
            time.sleep(0.05)
        time.sleep(0.5)
        signal.pthread_kill(threading.main_thread().ident, signal.SIGINT)

    threading.Thread(target=interrupt_when_serving, daemon=True).start()
    stdin = os.fdopen(read_end, "rb")
    try:
        code = serve.main(
            ["--worker", "process", "--state-root", str(tmp_path / "state"), "--",
             sys.executable, "-m", "sunglasses.proxy.echo_server", "--proc", str(proc_file)],
            stdin=stdin, stdout=io.BytesIO(), stderr=io.StringIO())
    finally:
        # The client reader thread is still blocked in a read of `stdin`; closing the read end first
        # would wait for it. Closing the write end gives it end-of-file and lets it go.
        os.close(write_end)
        try:
            info = json.loads(proc_file.read_text())
            os.killpg(info["pgid"], signal.SIGKILL)
        except Exception:
            pass
    stdin.close()
    assert code == 130, code
    assert seen == [130], seen
