"""The proxy's own state directories, when something else is in their place.

`approvals.Store` makes `<state root>/approvals` and `<state root>/captures`
with `mkdir(exist_ok=True)`, and it is built in `build_route`, AFTER the
upstream server has been spawned. So a regular file or a dangling link where
either directory belongs ends the proxy in a raw `FileExistsError` traceback,
and a server that does not die on EOF is left running: the teardown that stops
its group only wraps the session, and the session never began. An unlistable
`captures/` does not crash at all; the proxy's own capture write fails and the
client is told the SERVER was malformed.

Three properties, each a red before the fix (T11 R-SIB2, probe
warroom/RSIB_PROBE_a6cb9ede.txt, measured on main 30e0bd6):
* the refusal is a sentence that names the path, never a traceback;
* the upstream is reaped on every exit path, a crash included;
* a local write fault is never reported as MALFORMED_UPSTREAM, and every
  request the client sent is answered.

The `none` rows are the controls. They pass on the unfixed tree, which is what
proves each reading can see a pass at all.
"""
import io
import json
import os
import subprocess
import sys
import time

import pytest

pytest.importorskip("sunglasses.proxy.serve",
                    reason="the runnable artifact is the slice being specified")

OBSTRUCTIONS = [("approvals", "file"), ("approvals", "dangling"),
                ("captures", "file"), ("captures", "dangling")]
IDS = ["-".join(o) for o in OBSTRUCTIONS]


def _frame(obj):
    return (json.dumps(obj) + "\n").encode()


FRAMES = [
    _frame({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "1"}}}),
    _frame({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    _frame({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    _frame({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "hi"}}}),
]


def _obstruct(tmp_path, which, how):
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    if which is None:
        return state
    target = state / which
    if how == "file":
        target.write_text("not a directory\n")
    elif how == "dangling":
        target.symlink_to(tmp_path / "nowhere")
    elif how == "0000":
        target.mkdir()
        target.chmod(0o000)
    return state


def _server(tmp_path, linger):
    argv = [sys.executable, "-m", "sunglasses.proxy.echo_server",
            "--ingress", str(tmp_path / "ingress.log"),
            "--proc", str(tmp_path / "proc.json")]
    return argv + (["--linger"] if linger else [])


def _run(tmp_path, state, linger=False):
    proc = subprocess.run(
        [sys.executable, "-m", "sunglasses.proxy",
         "--state-root", str(state), "--"] + _server(tmp_path, linger),
        input=b"".join(FRAMES), capture_output=True, timeout=60)
    replies = [json.loads(line) for line in proc.stdout.splitlines()
               if line.strip()]
    return proc, replies


def _running(pid):
    """Alive and not a zombie. A killed child nobody has waited on still
    answers kill(pid, 0), so the process table is asked instead."""
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                           capture_output=True, text=True).stdout.strip()
    return bool(state) and not state.startswith("Z")


def _upstream_pid(tmp_path, wait=5.0):
    """The spawned server's pid, or None if it was never started. Never
    starting it is one of the ways to pass."""
    proc = tmp_path / "proc.json"
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if proc.exists() and proc.read_text():
            return json.loads(proc.read_text())["pid"]
        time.sleep(0.05)
    return None


def _still_running_after(pid, grace=3.0):
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if not _running(pid):
            return False
        time.sleep(0.05)
    return True


def _kill(pid):
    try:
        os.kill(pid, 9)
    except OSError:
        pass


def _unlock(tmp_path):
    for dp, dns, _ in os.walk(tmp_path):
        for d in dns:
            try:
                os.chmod(os.path.join(dp, d), 0o700)
            except OSError:
                pass


# ── a named refusal, never a traceback ───────────────────────────────────

@pytest.mark.parametrize("which,how", OBSTRUCTIONS, ids=IDS)
def test_an_obstructed_state_dir_is_a_named_refusal(tmp_path, which, how):
    state = _obstruct(tmp_path, which, how)
    proc, replies = _run(tmp_path, state)
    err = proc.stderr.decode(errors="replace")
    assert proc.returncode != 0
    assert "Traceback" not in err, err[-600:]
    assert err.startswith("sunglasses proxy:"), err[-600:]
    assert str(state / which) in err, err[-600:]


@pytest.mark.parametrize("which,how", OBSTRUCTIONS, ids=IDS)
def test_nothing_reaches_the_server_past_an_obstructed_state_dir(
        tmp_path, which, how):
    """Holds today and must keep holding: a fix that moves the store check
    must not let a frame through on the way."""
    state = _obstruct(tmp_path, which, how)
    _run(tmp_path, state)
    ingress = tmp_path / "ingress.log"
    assert not ingress.exists() or ingress.read_bytes() == b""


# ── the upstream is reaped on every exit path ────────────────────────────

@pytest.mark.parametrize("which,how", OBSTRUCTIONS + [(None, None)],
                         ids=IDS + ["control-none"])
def test_a_server_that_outlives_its_stdin_is_not_left_running(
        tmp_path, which, how):
    state = _obstruct(tmp_path, which, how)
    _run(tmp_path, state, linger=True)
    pid = _upstream_pid(tmp_path)
    if pid is None:
        return   # never spawned: nothing to orphan
    try:
        assert not _still_running_after(pid), \
            f"the upstream {pid} outlived the proxy, unmediated"
    finally:
        _kill(pid)


def test_the_upstream_is_stopped_when_wiring_the_route_raises(
        tmp_path, monkeypatch):
    """Every exit path, not only the one the probe found. Anything that
    raises between the spawn and the session must still stop the group."""
    from sunglasses.proxy import serve

    def boom(**_kwargs):
        raise RuntimeError("wiring failed")

    # The spawn is seen where it happens. The server's own pid file is not a
    # control here: a group stopped at once is stopped before the server has
    # written it, which read as "never spawned" on the very fix this pins.
    spawned = []
    real_popen = serve.subprocess.Popen

    def recording_popen(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        spawned.append(child)
        return child

    monkeypatch.setattr(serve, "build_route", boom)
    monkeypatch.setattr(serve.subprocess, "Popen", recording_popen)
    state = _obstruct(tmp_path, None, None)
    try:
        serve.main(["--state-root", str(state), "--"]
                   + _server(tmp_path, linger=True),
                   stdin=io.BytesIO(b""), stdout=io.BytesIO(),
                   stderr=io.StringIO())
    except Exception:
        pass
    assert len(spawned) == 1, "the upstream was never spawned (control)"
    pid = spawned[0].pid
    try:
        assert not _still_running_after(pid), \
            f"the upstream {pid} outlived a failed wiring"
    finally:
        _kill(pid)


# ── a local write fault is not the server's fault ────────────────────────

needs_modes = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root reads through mode 0000")


def _reason_codes(replies, state):
    codes = [r.get("error", {}).get("data", {}).get("reason_code")
             for r in replies]
    for log in (state / "receipts").glob("*.jsonl"):
        for line in log.read_text().splitlines():
            if line.strip():
                codes.append(json.loads(line).get("reason_code"))
    return codes


@needs_modes
@pytest.mark.parametrize("linger", [False, True], ids=["echo", "linger"])
@pytest.mark.parametrize("which", ["captures", None],
                         ids=["captures-0000", "control-none"])
def test_a_capture_that_cannot_be_written_is_not_blamed_on_the_server(
        tmp_path, which, linger):
    state = _obstruct(tmp_path, which, "0000")
    try:
        _proc, replies = _run(tmp_path, state, linger=linger)
    finally:
        _unlock(tmp_path)
    codes = _reason_codes(replies, state)
    assert "MALFORMED_UPSTREAM" not in codes, codes


@needs_modes
@pytest.mark.parametrize("linger", [False, True], ids=["echo", "linger"])
@pytest.mark.parametrize("which", ["captures", None],
                         ids=["captures-0000", "control-none"])
def test_every_request_read_before_the_close_is_answered(
        tmp_path, which, linger):
    """Gate per R66 (pending T9, A recommended). A close answers every id the
    proxy READ and forwards nothing after it; a request still unread in the
    pipe is not read (serve._drain_client stops on any close, as it does for
    the receipt fault). So the tripping list is answered with the proxy's own
    cause, and the call behind it is answered or never reaches the server."""
    state = _obstruct(tmp_path, which, "0000")
    try:
        _proc, replies = _run(tmp_path, state, linger=linger)
    finally:
        _unlock(tmp_path)
    answered = [r.get("id") for r in replies if "id" in r]
    assert len(answered) == len(set(answered)), replies
    if which is None:
        assert sorted(answered) == [1, 2, 3], replies   # control
        return
    assert 1 in answered and 2 in answered, replies
    (listed,) = [r for r in replies if r.get("id") == 2]
    assert listed.get("error", {}).get("data", {}).get(
        "reason_code") == "STATE_IO_ERROR", listed
    if 3 not in answered:
        ingress = tmp_path / "ingress.log"
        seen = ingress.read_bytes() if ingress.exists() else b""
        assert b'"tools/call"' not in seen, "a call went on after the close"


@needs_modes
@pytest.mark.parametrize("linger", [False, True], ids=["echo", "linger"])
def test_a_capture_that_cannot_be_written_exits_nonzero(tmp_path, linger):
    """T8.R14: a fault is nonzero always. Today the lingering run exits 0
    with no reason recorded."""
    state = _obstruct(tmp_path, "captures", "0000")
    try:
        proc, _replies = _run(tmp_path, state, linger=linger)
    finally:
        _unlock(tmp_path)
    assert proc.returncode != 0


@needs_modes
@pytest.mark.parametrize("linger", [False, True], ids=["echo", "linger"])
def test_the_receipt_names_the_capture_fault(tmp_path, linger):
    """T9 ruling 64: the session closes on the proxy's own cause, and the run
    log says which, so a reader of the receipt is not left to guess."""
    state = _obstruct(tmp_path, "captures", "0000")
    try:
        _proc, replies = _run(tmp_path, state, linger=linger)
    finally:
        _unlock(tmp_path)
    assert "STATE_IO_ERROR" in _reason_codes(replies, state)


def test_the_run_log_carries_the_catalog_it_was_written_under(tmp_path):
    """Ruling 64: a new reason is a new catalog, sg-proxy-catalog/2."""
    state = _obstruct(tmp_path, None, None)
    _run(tmp_path, state)
    (log,) = (state / "receipts").glob("*.jsonl")
    header = json.loads(log.read_text().splitlines()[0])
    assert header.get("catalog_version") == "sg-proxy-catalog/2", header


# ── the approval store read and written through a fault ───────────────────

SHA = "a" * 64


@needs_modes
def test_an_unlistable_approvals_dir_is_invalid_not_absent(tmp_path):
    """T507 in the same function: an unreadable record is not an absent one.
    `exists()` answers False on EACCES, so an approved server whose approvals
    directory cannot be listed read as never approved."""
    from sunglasses.proxy import approvals

    store = approvals.Store(tmp_path / "state", server_id="s")
    store.write_raw({"approved_by": "human", "snapshot_sha256": SHA,
                     "server_identity": "s", "tools": {}})
    assert store._record_or_reason()[1] is None   # control: readable, valid
    store.approvals.chmod(0o000)
    try:
        assert store._record_or_reason() == (None, approvals.INVALID)
        assert store.state() == approvals.INVALID
    finally:
        store.approvals.chmod(0o700)


def test_control_no_record_is_still_absent(tmp_path):
    from sunglasses.proxy import approvals

    store = approvals.Store(tmp_path / "state", server_id="s")
    assert store._record_or_reason() == (None, None)
    assert store.state() == approvals.UNAPPROVED


def _approve(state):
    from sunglasses.proxy import commands

    out, err = io.StringIO(), io.StringIO()
    code = commands._approve("s", {"snapshot": SHA, "state-root": str(state)},
                             out, err, confirm=lambda: True)
    return code, err.getvalue()


def _captured(tmp_path):
    state = tmp_path / "state"
    (state / "captures").mkdir(parents=True)
    (state / "captures" / f"s.{SHA}.json").write_text(
        json.dumps({"tools_by_name": {}}))
    return state


@needs_modes
def test_approve_names_an_approvals_dir_it_cannot_write(tmp_path):
    state = _captured(tmp_path)
    (state / "approvals").mkdir()
    (state / "approvals").chmod(0o500)
    try:
        code, err = _approve(state)
    finally:
        (state / "approvals").chmod(0o700)
    assert code == 1, err
    assert err.startswith("sunglasses proxy:") and str(state / "approvals") in err, err
    assert not (state / "approvals" / "s.json").exists()


@pytest.mark.parametrize("how", ["file", "dangling"])
def test_approve_names_an_obstructed_approvals_dir(tmp_path, how):
    state = _captured(tmp_path)
    _obstruct(tmp_path, "approvals", how)
    code, err = _approve(state)
    assert code == 1, err
    assert err.startswith("sunglasses proxy:") and str(state / "approvals") in err, err


def test_control_approve_writes_the_record(tmp_path):
    state = _captured(tmp_path)
    code, err = _approve(state)
    assert code == 0, err
    assert (state / "approvals" / "s.json").exists()
