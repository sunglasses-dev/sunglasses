"""A route that fails to wire must not leave the warm spare behind.

With `--worker process`, `build_route` starts the ProcessScan spare BEFORE it
builds the Route. The teardown that closes the spare runs only once a session
exists, so a raise out of `Route(...)` left the spare running with nobody to
close it. MEASURED 9-25 on the 0.6.1 stack: the proxy exited 1 and the spare
was still alive, reparented to pid 1, still loading its engine.

The rows call `build_route` itself, because that is where the spare is made
and where it has to be closed; what `main` does with the raise afterwards is
another row's business. Each row holds a reference to the spare, as a
longer-lived caller would, so it measures the close and not the garbage
collector closing a pipe.
"""
import io
import os
import sys
import threading
import time

import pytest

from sunglasses.proxy import pump, route, serve, worker_process

UPSTREAM = [sys.executable, "-c", "import sys; sys.stdin.buffer.read()"]


class WiringFailed(Exception):
    pass


class CloseFailed(Exception):
    pass


def _alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _gone(pid, within=0.5):
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.02)
    return False


def _record_spares(monkeypatch):
    spares = []
    real_spawn = worker_process._spawn

    def recording_spawn(argv):
        spare = real_spawn(argv)
        spares.append(spare)
        return spare

    monkeypatch.setattr(worker_process, "_spawn", recording_spawn)
    return spares


def _wiring_fails(monkeypatch):
    def boom(self, *args, **kwargs):
        raise WiringFailed("wiring failed")
    monkeypatch.setattr(route.Route, "__init__", boom)


def _build(tmp_path):
    return serve.build_route(session=pump.Session(strict=True), log=None,
                             upstream_argv=UPSTREAM,
                             upstream_write=lambda raw: None,
                             client_write=lambda raw: None,
                             root=str(tmp_path), worker="process")


def _reap(spares):
    for child, ready_r in spares:
        if _alive(child.pid):
            child.kill()
        child.wait()
        try:
            os.close(ready_r)
        except OSError:
            pass


def test_the_spare_is_closed_when_wiring_the_route_raises(tmp_path, monkeypatch):
    spares = _record_spares(monkeypatch)
    _wiring_fails(monkeypatch)
    try:
        with pytest.raises(WiringFailed):
            _build(tmp_path)
        assert len(spares) == 1, "no spare was started (control)"
        pid = spares[0][0].pid
        assert _gone(pid), f"the spare {pid} outlived a failed wiring"
    finally:
        _reap(spares)


def test_a_close_that_raises_does_not_hide_why_the_wiring_failed(
        tmp_path, monkeypatch):
    """The close runs while the wiring error is being handled. If it raised
    through, the caller would see the close's error and not the one that says
    what went wrong, so the wiring error is the one that leaves, carrying the
    close failure with it where the version can carry it."""
    spares = _record_spares(monkeypatch)
    _wiring_fails(monkeypatch)
    real_close = worker_process.ProcessScan.close

    def close_then_raise(self):
        real_close(self)
        raise CloseFailed("close failed")

    monkeypatch.setattr(worker_process.ProcessScan, "close", close_then_raise)
    try:
        with pytest.raises(WiringFailed) as caught:
            _build(tmp_path)
        assert len(spares) == 1, "no spare was started (control)"
        # Stimulus proof: the close ran, so the raise above is the one it
        # would have hidden.
        assert _gone(spares[0][0].pid), "the close never ran (stimulus)"
        if sys.version_info >= (3, 11):
            notes = getattr(caught.value, "__notes__", [])
            assert any("close failed" in note for note in notes), notes
    finally:
        _reap(spares)


def test_control_the_spare_is_closed_when_the_session_ends(tmp_path, monkeypatch):
    """The path that already closed it: a session that ran and ended."""
    spares = _record_spares(monkeypatch)
    # `main` sets the module's `_FINISHED` on its way out, and while it is set
    # `exit_process` leaves with `os._exit`: a later in-process test that calls
    # it would take the whole runner down with a clean exit and no summary.
    # This run gets its own event; the module's stays clear.
    monkeypatch.setattr(serve, "_FINISHED", threading.Event())
    serve.main(["--worker", "process", "--state-root", str(tmp_path),
                "--"] + UPSTREAM,
               stdin=io.BytesIO(b""), stdout=io.BytesIO(), stderr=io.StringIO())
    try:
        assert len(spares) == 1, "no spare was started (control)"
        assert _gone(spares[0][0].pid), "the spare outlived the teardown"
    finally:
        _reap(spares)
