"""`doctor --launch-routes`: start each wrapped route in the user's file once.

Every row that needs a process wires a real server with the real `install`, in an
isolated HOME, and starts it through the real proxy. The rows are paired: each
refusal (a project file is never started, a cap, a quiet route) sits beside the row
that shows the same setup DOES start when it is allowed, because a launcher that
never starts anything passes every refusal row.
"""
import ast
import hashlib
import inspect
import json
import os
import re
import signal
import subprocess
import sys
import textwrap
import threading
import time
import types
from pathlib import Path

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)

from sunglasses.proxy import doctor, live_selftest as live, route_launch  # noqa: E402
from sunglasses.proxy._deadline import REAP_S, Clock  # noqa: E402

pytestmark = pytest.mark.skipif(not (hasattr(os, "killpg") and os.name == "posix"),
                                reason="launching a route needs process groups")

_CONTROLS = {name: "FAIL" for name in doctor.REQUIRED_CONTROLS}
_PASSING = {name: "PASS" for name in doctor.SELF_TEST_CHECKS}


def _self_test():
    """A self-test that passes without spawning, so these rows are about routes."""
    return True, dict(_CONTROLS), dict(_PASSING), {"deadline_ms": 1}


# A user's server. It writes a file when it starts, so "was it started" is a fact on
# disk and not an inference from a verdict. `mode` picks how it misbehaves.
_SERVER = textwrap.dedent('''
    import json, os, sys, time
    mode, probe = sys.argv[1], sys.argv[2]

    def say(message):
        sys.stdout.write(json.dumps(message) + "\\n")
        sys.stdout.flush()

    with open(probe, "w") as handle:
        json.dump({"argv": sys.argv[1:], "cwd": os.getcwd(), "pid": os.getpid(),
                   "env": os.environ.get("ROUTE_PROBE", ""),
                   "home": os.environ.get("HOME", "")}, handle)
    if mode == "silent":
        time.sleep(120)
    for raw in sys.stdin:
        try:
            message = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(message, dict) or "id" not in message:
            continue
        method = message.get("method")
        if method == "initialize":
            say({"jsonrpc": "2.0", "id": message["id"], "result": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "serverInfo": {"name": "up", "version": "1"}}})
            if mode == "exit_after_init":
                sys.exit(0)
        elif method == "ping":
            if mode == "swallow_ping":
                continue
            if mode == "error_ping":
                say({"jsonrpc": "2.0", "id": message["id"],
                     "error": {"code": -32603, "message": "no"}})
                continue
            say({"jsonrpc": "2.0", "id": message["id"], "result": {}})
        elif method == "tools/list":
            say({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": []}})
        else:
            say({"jsonrpc": "2.0", "id": message["id"],
                 "error": {"code": -32601, "message": "unknown"}})
    if mode == "ignore_eof":
        # Its input has closed and it keeps running: only the proxy's own teardown ends it.
        time.sleep(120)
''')


class World:
    """An isolated HOME with a user file, a project file and a scratch folder."""

    def __init__(self, tmp_path, monkeypatch):
        self.root = tmp_path
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.tmpdir = tmp_path / "tmp"
        self.tmpdir.mkdir()
        self.server = tmp_path / "server.py"
        self.server.write_text(_SERVER)
        monkeypatch.setenv("HOME", str(self.home))
        monkeypatch.setenv("PYTHONPATH", REPO)
        monkeypatch.setenv("PYTHONDONTWRITEBYTECODE", "1")
        monkeypatch.setenv("TMPDIR", str(self.tmpdir))
        monkeypatch.setattr("tempfile.tempdir", None)
        self.env = {**os.environ, "HOME": str(self.home), "PYTHONPATH": REPO,
                    "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(self.tmpdir)}

    def probe(self, name):
        return self.root / f"{name}.probe"

    def wire(self, cfg, name, mode="ok", extra_args=(), **extra):
        """Write one server into `cfg` and wrap it with the real `install`."""
        entry = {"command": sys.executable,
                 "args": [str(self.server), mode, str(self.probe(name)), *extra_args], **extra}
        doc = json.loads(cfg.read_text()) if cfg.exists() else {"mcpServers": {}}
        doc["mcpServers"][name] = entry
        cfg.write_text(json.dumps(doc))
        done = subprocess.run([sys.executable, "-m", "sunglasses.cli", "install", name,
                               "--config", str(cfg)], capture_output=True, text=True,
                              env=self.env, cwd=str(self.root))
        assert done.returncode == 0, (done.stdout, done.stderr)
        return cfg

    def user_file(self):
        return self.home / ".claude.json"

    def project_file(self):
        return self.root / "project" / ".mcp.json"

    def run(self, sources, **kwargs):
        return doctor.run(sources=sources, self_test=_self_test, launch_routes=True, **kwargs)


@pytest.fixture
def world(tmp_path, monkeypatch):
    return World(tmp_path, monkeypatch)


def _tree(path):
    """Every path under `path` with a digest of its bytes, so a changed (even a same-size)
    or added file shows."""
    out = {}
    if not path.exists():
        return out
    for item in sorted(path.rglob("*")):
        out[str(item.relative_to(path))] = (
            hashlib.sha256(item.read_bytes()).hexdigest() if item.is_file() else "dir")
    return out


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


# ── the verdicts ─────────────────────────────────────────────────────────

def test_one_wired_route_that_answers_passes_and_the_run_exits_zero(world):
    world.wire(world.user_file(), "demo")
    report = world.run([("user", world.user_file())])
    [row] = report.outcome.per_wrapper
    assert row["result"] == "PASS" and "reason" not in row
    assert report.exit_code == 0 and report.outcome.aggregate == doctor.ROUTE_VERIFIED
    assert world.probe("demo").exists(), "the verdict says PASS but the server never started"


def test_a_route_that_swallows_the_ping_fails_and_the_run_exits_one(world):
    world.wire(world.user_file(), "quiet", mode="swallow_ping")
    report = world.run([("user", world.user_file())])
    [row] = report.outcome.per_wrapper
    assert row["result"] == "FAIL", row
    assert report.exit_code == doctor.EXIT_FAILED
    assert world.probe("quiet").exists()


def test_a_ping_answered_with_an_error_is_a_fail_not_a_pass(world):
    world.wire(world.user_file(), "erring", mode="error_ping")
    report = world.run([("user", world.user_file())])
    assert report.outcome.per_wrapper[0]["result"] == "FAIL"


def test_a_route_that_never_answers_initialize_is_not_run_and_the_run_exits_three(
        world, monkeypatch):
    monkeypatch.setattr(live, "FIRST_REPLY_S", 1.0)
    world.wire(world.user_file(), "mute", mode="silent")
    report = world.run([("user", world.user_file())])
    [row] = report.outcome.per_wrapper
    assert row["result"] == "NOT_RUN" and row["reason"] == doctor.REASON_NO_INITIALIZE, row
    assert report.exit_code == doctor.EXIT_DOUBT
    assert world.probe("mute").exists(), "it was started, and then said nothing"


# ── what is never started ───────────────────────────────────────────────

def test_a_project_file_entry_is_never_started_even_with_the_flag(world):
    world.project_file().parent.mkdir()
    world.wire(world.project_file(), "cloned")
    report = world.run([("project", world.project_file())])
    [row] = report.outcome.per_wrapper
    assert row["result"] == "NOT_RUN" and row["reason"] == doctor.REASON_NOT_USER_FILE, row
    assert not world.probe("cloned").exists(), "a project-file entry was started"
    assert report.exit_code == doctor.EXIT_DOUBT


def test_the_same_entry_in_the_user_file_is_started(world):
    """The control for the row above: the refusal is about the file, not the entry."""
    world.wire(world.user_file(), "cloned")
    world.run([("user", world.user_file())])
    assert world.probe("cloned").exists()


def test_a_file_named_with_config_is_not_the_user_file_unless_it_is(world):
    elsewhere = world.root / "other.json"
    world.wire(elsewhere, "named")
    report = world.run([("config", elsewhere)])
    assert report.outcome.per_wrapper[0]["reason"] == doctor.REASON_NOT_USER_FILE
    assert not world.probe("named").exists()
    # The user's own file, named by path, is the user's file whatever it is labelled.
    world.wire(world.user_file(), "mine")
    report = world.run([("config", world.user_file())])
    assert report.outcome.per_wrapper[0]["result"] == "PASS"
    assert world.probe("mine").exists()


def test_without_the_flag_nothing_is_started_and_the_line_names_the_flag(world):
    world.wire(world.user_file(), "demo")
    done = subprocess.run([sys.executable, "-m", "sunglasses.cli", "doctor", "--config",
                           str(world.user_file())], capture_output=True, text=True,
                          env=world.env, cwd=str(world.root))
    assert done.returncode == 3, (done.stdout, done.stderr)
    assert not world.probe("demo").exists(), "plain doctor started a server"
    assert "--launch-routes" in done.stdout
    assert "route NOT_RUN" in done.stdout
    assert "will start" not in done.stderr


# ── caps ────────────────────────────────────────────────────────────────

def test_the_route_after_the_cap_is_not_started_and_says_why(world, monkeypatch):
    monkeypatch.setattr(route_launch, "MAX_ROUTES", 2)
    for name in ("a", "b", "c"):
        world.wire(world.user_file(), name)
    report = world.run([("user", world.user_file())])
    rows = {r["name"]: r for r in report.outcome.per_wrapper}
    assert rows["a"]["result"] == rows["b"]["result"] == "PASS"
    assert rows["c"]["result"] == "NOT_RUN" and rows["c"]["reason"] == doctor.REASON_CAP
    assert not world.probe("c").exists()
    assert report.exit_code == doctor.EXIT_DOUBT


def test_a_route_that_uses_its_allowance_is_not_run_and_is_stopped(world, monkeypatch):
    # 9.5 s less the margin and the held-back teardown leaves a 1 s wait for `initialize`.
    monkeypatch.setattr(route_launch, "ROUTE_S", 9.5)
    world.wire(world.user_file(), "slow", mode="silent")
    report = world.run([("user", world.user_file())])
    [row] = report.outcome.per_wrapper
    assert row["result"] == "NOT_RUN" and row["reason"] == doctor.REASON_OUT_OF_TIME, row
    pid = json.loads(world.probe("slow").read_text())["pid"]
    assert _gone(pid, within=1.0), "the route's server was left running"


# ── what it leaves, what it prints ──────────────────────────────────────

def test_one_launched_route_leaves_the_state_tree_and_the_private_folder_as_it_found_them(world):
    world.wire(world.user_file(), "demo")
    state = world.home / ".sunglasses"
    before = _tree(state)
    leftovers = _tree(world.tmpdir)
    assert before, "the wiring writes install records; this row compares against them"
    report = world.run([("user", world.user_file())])
    assert report.outcome.per_wrapper[0]["result"] == "PASS"
    assert _tree(state) == before, "a launched route wrote under ~/.sunglasses"
    assert _tree(world.tmpdir) == leftovers, "the private folder was left behind"


def test_the_control_for_the_row_above_a_route_started_without_the_scratch_root_does_write(
        world):
    """Without `--state-root` the proxy writes a receipt under HOME; the row above
    would pass on a doctor that never started anything if this one did not."""
    world.wire(world.user_file(), "demo")
    state = world.home / ".sunglasses"
    before = _tree(state)
    argv = [sys.executable, "-m", "sunglasses.proxy", "--", sys.executable,
            str(world.server), "ok", str(world.probe("bare"))]
    peer = live._Peer(argv, world.env, None)
    try:
        peer.send(live._INIT)
        assert peer.reply(1, 20)[0] is not None
        peer.close_stdin()
        peer.wait(5)
    finally:
        peer.kill()
    assert _tree(state) != before, "the proxy did not write: the row above proves nothing"


def test_the_users_command_environment_and_folder_reach_the_server_untouched(world):
    folder = world.root / "work"
    folder.mkdir()
    world.wire(world.user_file(), "demo", extra_args=("--flag", "value"),
               env={"ROUTE_PROBE": "from-the-entry"}, cwd=str(folder))
    world.run([("user", world.user_file())])
    seen = json.loads(world.probe("demo").read_text())
    assert seen["argv"][2:] == ["--flag", "value"], seen
    assert seen["env"] == "from-the-entry"
    assert os.path.realpath(seen["cwd"]) == os.path.realpath(str(folder))
    assert seen["home"] == str(world.home), "HOME was moved"


def test_a_scratch_folder_for_one_route_is_private_to_the_user(world, monkeypatch):
    seen = {}

    def look(argv, env, cwd, budget, notes=None, info=None):
        root = argv[argv.index("--state-root") + 1]
        seen["mode"] = os.stat(root).st_mode & 0o777
        seen["parent"] = os.stat(os.path.dirname(root)).st_mode & 0o777
        return True, {"initialized": "PASS", "deadline": "PASS", "disconnect": "PASS"}, ""

    monkeypatch.setattr(route_launch, "_drive_route", look)
    world.wire(world.user_file(), "demo")
    world.run([("user", world.user_file())])
    assert seen == {"mode": 0o700, "parent": 0o700}


def test_the_scratch_root_is_the_last_state_root_the_proxy_reads():
    argv = [sys.executable, "-m", "sunglasses.proxy", "--state-root", "/theirs", "--",
            "npx", "server", "--state-root", "/the-servers-own"]
    out = route_launch._with_state_root(argv, "/scratch")
    split = out.index("--")
    assert out[split - 2:split] == ["--state-root", "/scratch"]
    assert out[split:] == argv[argv.index("--"):], "what follows the -- changed"


def test_only_the_programs_file_name_is_printed_never_arguments_or_environment(world):
    secret = "hunter2-token-value"
    world.wire(world.user_file(), "demo", extra_args=(f"--token={secret}",),
               env={"ROUTE_PROBE": secret})
    done = subprocess.run([sys.executable, "-m", "sunglasses.cli", "doctor", "--config",
                           str(world.user_file()), "--launch-routes", "--json"],
                          capture_output=True, text=True, env=world.env, cwd=str(world.root))
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert secret not in done.stdout and secret not in done.stderr
    assert "will start: demo (config) -> " in done.stderr or "will start: demo (user) -> " in done.stderr
    json.loads(done.stdout)     # the announcement is on stderr, so --json stays one document


def test_a_name_with_an_escape_sequence_cannot_reach_the_terminal():
    assert route_launch._shown("a\x1b[31mb\nc") == "a??31mb?c"
    assert route_launch._shown("") == "?"
    assert len(route_launch._shown("x" * 500)) == 48


# ── the way out ─────────────────────────────────────────────────────────

def test_ctrl_c_mid_launch_exits_130_with_one_line_and_leaves_nothing(world):
    world.wire(world.user_file(), "stuck", mode="silent")
    proc = subprocess.Popen([sys.executable, "-m", "sunglasses.cli", "doctor", "--config",
                             str(world.user_file()), "--launch-routes"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env=world.env, cwd=str(world.root))
    probe = world.probe("stuck")
    deadline = time.monotonic() + 30
    while not probe.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert probe.exists(), "the route was never started, so there is nothing to interrupt"
    pid = json.loads(probe.read_text())["pid"]
    proc.send_signal(signal.SIGINT)
    out, err = proc.communicate(timeout=30)
    assert proc.returncode == 130, (proc.returncode, out, err)
    assert "Traceback" not in err and err.strip().count("\n") <= 1 + err.count("will start"), err
    assert "interrupted" in err
    deadline = time.monotonic() + 3
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _alive(pid), "the route's server was left running"
    assert _tree(world.tmpdir) == {}, "the private folder was left behind"


def test_an_environment_name_that_env_would_read_as_an_option_is_not_started(world):
    world.wire(world.user_file(), "demo", env={"-i": "x"})
    report = world.run([("user", world.user_file())])
    [row] = report.outcome.per_wrapper
    assert row["result"] == "NOT_RUN" and row["reason"] == doctor.REASON_COULD_NOT_START
    assert not world.probe("demo").exists()


# ── review r1: provenance, the process list, the clock ──────────────────

def test_a_project_file_that_is_a_link_to_the_user_file_is_still_a_project_file(world):
    world.wire(world.user_file(), "linked")
    world.project_file().parent.mkdir()
    world.project_file().symlink_to(world.user_file())
    report = world.run([("project", world.project_file())])
    [row] = report.outcome.per_wrapper
    assert row["result"] == "NOT_RUN" and row["reason"] == doctor.REASON_NOT_USER_FILE, row
    assert not world.probe("linked").exists(), "a project link to the user file started a server"
    # The control: the user file itself, read under its own label, starts it.
    world.run([("user", world.user_file())])
    assert world.probe("linked").exists()


def test_when_the_process_list_cannot_be_read_nothing_is_started(world, monkeypatch):
    world.wire(world.user_file(), "demo")
    monkeypatch.setattr(route_launch, "_process_table", lambda *_a, **_k: None)
    report = world.run([("user", world.user_file())])
    [row] = report.outcome.per_wrapper
    assert row["result"] == "NOT_RUN" and row["reason"] == doctor.REASON_UNSUPPORTED, row
    assert not world.probe("demo").exists(), "a server was started that could not be stopped"
    assert report.exit_code == doctor.EXIT_DOUBT


@pytest.mark.skipif(not os.path.isdir("/proc"), reason="/proc is the Linux fallback")
def test_without_ps_the_process_table_is_read_from_proc_and_a_route_is_still_stopped(
        world, monkeypatch):
    monkeypatch.setattr(Clock, "run", lambda *_a, **_k: None)  # `ps` cannot be run
    assert os.getpid() in route_launch._process_table(Clock(3.0))
    world.wire(world.user_file(), "stuck", mode="silent")
    # A short wait for `initialize` at the production route limit, and a proxy teardown too
    # short to stop an unseen server: the server can only be gone if the /proc walk named its
    # group, so the row cannot pass on the proxy's own stop.
    monkeypatch.setattr(route_launch, "INITIALIZE_S", 2.0)
    monkeypatch.setattr(route_launch, "PROXY_TEARDOWN_S", 0.3)
    world.run([("user", world.user_file())])
    pid = json.loads(world.probe("stuck").read_text())["pid"]
    deadline = time.monotonic() + 3
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _alive(pid), "the server was left running with ps unavailable"


def test_a_ping_nobody_answers_is_a_fail_even_when_the_allowance_is_nearly_spent(
        world, monkeypatch):
    """The allowance limits the wait for `initialize`; a known later failure stays a FAIL."""
    monkeypatch.setattr(route_launch, "ROUTE_S", 11.0)
    world.wire(world.user_file(), "quiet", mode="swallow_ping")
    report = world.run([("user", world.user_file())])
    assert report.outcome.per_wrapper[0]["result"] == "FAIL"
    assert report.exit_code == doctor.EXIT_FAILED


def test_a_route_is_started_only_if_a_whole_allowance_is_left(world, monkeypatch):
    monkeypatch.setattr(route_launch, "TOTAL_S", 10.0)
    world.wire(world.user_file(), "late")
    report = world.run([("user", world.user_file())])
    [row] = report.outcome.per_wrapper
    assert row["result"] == "NOT_RUN" and row["reason"] == doctor.REASON_CAP
    assert not world.probe("late").exists()


def test_terminate_exits_143_with_one_line_and_leaves_nothing(world):
    world.wire(world.user_file(), "stuck", mode="silent")
    proc = subprocess.Popen([sys.executable, "-m", "sunglasses.cli", "doctor", "--config",
                             str(world.user_file()), "--launch-routes"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env=world.env, cwd=str(world.root))
    probe = world.probe("stuck")
    deadline = time.monotonic() + 30
    while not probe.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert probe.exists()
    pid = json.loads(probe.read_text())["pid"]
    proc.send_signal(signal.SIGTERM)
    out, err = proc.communicate(timeout=30)
    assert proc.returncode == 143, (proc.returncode, out, err)
    assert "Traceback" not in err and "terminated" in err
    deadline = time.monotonic() + 3
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _alive(pid)
    assert _tree(world.tmpdir) == {}


# ── review r2: ownership kept, provenance of a named file, the clock ────

def _table_lost_after(monkeypatch, reads):
    """The process table answers `reads` times (the preflight is the first), then not at all."""
    real = route_launch._process_table
    seen = {"n": 0}

    def table(*args, **kwargs):
        seen["n"] += 1
        return real(*args, **kwargs) if seen["n"] <= reads else None

    monkeypatch.setattr(route_launch, "_process_table", table)


def _table_lost_after_seconds(monkeypatch, seconds):
    """The process table answers until `seconds` after the first read, then not at all."""
    real = route_launch._process_table
    first = {}

    def table(*args, **kwargs):
        first.setdefault("at", time.monotonic())
        if time.monotonic() - first["at"] > seconds:
            return None
        return real(*args, **kwargs)

    monkeypatch.setattr(route_launch, "_process_table", table)


def _gone(pid, within=4.0):
    deadline = time.monotonic() + within
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    return not _alive(pid)


def test_a_server_seen_while_the_route_ran_is_stopped_after_the_process_list_is_lost(
        world, monkeypatch):
    """Ownership is kept: the groups seen before the list was lost are the ones stopped.
    The proxy's own stop is made too short to rescue a server nobody has named, so the server
    can only be gone if the groups seen before the loss were kept (a mutant that replaces the
    kept set with each new reading leaves it running)."""
    monkeypatch.setattr(route_launch, "INITIALIZE_S", 2.0)
    monkeypatch.setattr(route_launch, "PROXY_TEARDOWN_S", 0.3)
    _table_lost_after_seconds(monkeypatch, 0.9)
    world.wire(world.user_file(), "kept", mode="silent")
    report = world.run([("user", world.user_file())])
    [row] = report.outcome.per_wrapper
    assert row["result"] == "NOT_RUN", row
    assert _gone(json.loads(world.probe("kept").read_text())["pid"]), \
        "a server whose group was seen was left running"


def test_a_route_whose_server_group_was_never_seen_is_not_called_clean(world, monkeypatch):
    """The list is read once, then lost: an answering server cannot be shown gone, so the
    route is a FAIL (it answered), and the server is still gone because the proxy stops it."""
    _table_lost_after(monkeypatch, 1)
    world.wire(world.user_file(), "unseen")
    report = world.run([("user", world.user_file())])
    [row] = report.outcome.per_wrapper
    assert row["result"] == "FAIL", row
    assert report.exit_code == doctor.EXIT_FAILED
    assert _gone(json.loads(world.probe("unseen").read_text())["pid"])


def test_a_silent_route_whose_group_was_never_seen_is_reported_as_possibly_running(
        world, monkeypatch, capsys):
    """The list is lost before the server's group is seen and the server will not answer:
    the proxy is closed and, when it has not left by itself in time, killed; the run then says
    the server may still be there. The teardown allowance is cut to 0.5 s to reach that case:
    the proxy needs about 5 s."""
    monkeypatch.setattr(route_launch, "INITIALIZE_S", 1.0)
    monkeypatch.setattr(route_launch, "PROXY_TEARDOWN_S", 0.5)
    _table_lost_after(monkeypatch, 1)
    world.wire(world.user_file(), "dark", mode="silent")
    try:
        with route_launch.RouteLauncher() as launcher:
            [entry] = [e for e in doctor.read_sources([("user", world.user_file())])[0]]
            launcher(entry)
        assert "may still be running" in capsys.readouterr().err
    finally:
        pid = json.loads(world.probe("dark").read_text())["pid"]
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except OSError:
            pass


def test_a_server_that_answers_and_exits_at_once_is_a_fail_not_a_lack_of_a_list(world):
    world.wire(world.user_file(), "brief", mode="exit_after_init")
    report = world.run([("user", world.user_file())])
    [row] = report.outcome.per_wrapper
    assert row["result"] == "FAIL", row
    assert report.exit_code == doctor.EXIT_FAILED


def test_a_project_file_named_with_config_is_still_a_project_file(world):
    """`--config` does not turn a project `.mcp.json` into the user's file, by link or name."""
    world.wire(world.user_file(), "linked")
    world.project_file().parent.mkdir()
    world.project_file().symlink_to(world.user_file())
    for label, path in (("config", world.project_file()),
                        ("config", world.root / "project" / ".." / "home" / ".claude.json")):
        report = world.run([(label, path)])
        [row] = report.outcome.per_wrapper
        assert row["result"] == "NOT_RUN" and row["reason"] == doctor.REASON_NOT_USER_FILE, row
        assert not world.probe("linked").exists(), f"{path} started a server"
    done = subprocess.run([sys.executable, "-m", "sunglasses.cli", "doctor", "--config",
                           str(world.project_file()), "--launch-routes"],
                          capture_output=True, text=True, env=world.env, cwd=str(world.root))
    assert not world.probe("linked").exists(), (done.stdout, done.stderr)
    assert done.returncode == 3, (done.stdout, done.stderr)
    # The control: the user file's own name, given as --config, starts it.
    done = subprocess.run([sys.executable, "-m", "sunglasses.cli", "doctor", "--config",
                           str(world.user_file()), "--launch-routes"],
                          capture_output=True, text=True, env=world.env, cwd=str(world.root))
    assert world.probe("linked").exists(), (done.stdout, done.stderr)


# ── the clocks: one deadline per route, the proxy's teardown, the written frames ───────

def test_the_constants_of_one_route_fit_inside_its_deadline():
    """With the group unseen the wait for `initialize` and the proxy's teardown fit; with it
    seen, the waits after `initialize` and the groups going fit in what the wait leaves."""
    assert route_launch.INITIALIZE_S + route_launch.PROXY_TEARDOWN_S <= route_launch.ROUTE_S \
        - route_launch.ROUTE_MARGIN_S
    assert (route_launch.INITIALIZE_S + route_launch.READ_S + route_launch.PING_WAIT_S
            + route_launch.PROXY_TEARDOWN_S + live.GROUP_GONE_S) <= route_launch.ROUTE_S + 3.0
    assert route_launch.PING_WAIT_S * 1000 > doctor.DEADLINE_BOUND_MS


def test_the_proxy_teardown_allowance_covers_what_the_proxy_itself_waits():
    """`PROXY_TEARDOWN_S` is the proxy's own teardown plus a margin, read from the proxy's
    modules: the join of its reader thread (`serve.py`) and the grace of `stop_group`
    (`supervisor.py`). A change there fails this row instead of voiding the reserve."""
    from sunglasses.proxy import bounds, serve, supervisor
    source = inspect.getsource(serve)
    [join] = re.findall(r"reader\.join\(timeout=bounds\.KILL_GRACE_MS / 1000\s+"
                        r"if stalled and stalled\[0\] == \"SCAN_DEADLINE\" else (\d+(?:\.\d+)?)\)",
                        source)
    join_s = max(float(join), bounds.KILL_GRACE_MS / 1000)
    grace_s = inspect.signature(supervisor.stop_group).parameters["grace_ms"].default / 1000
    assert route_launch.PROXY_TEARDOWN_S >= join_s + grace_s + 1.0, (join_s, grace_s)


def test_a_server_that_ignores_a_closed_input_passes_and_the_run_says_the_proxy_stopped_it(
        world, capsys):
    """It answered, then its input closed and it kept running: the proxy stops it in about
    5 s, which is later than a prompt exit. Not a FAIL: the proxy path worked as designed."""
    world.wire(world.user_file(), "stays", mode="ignore_eof")
    started = time.monotonic()
    report = world.run([("user", world.user_file())])
    elapsed = time.monotonic() - started
    [row] = report.outcome.per_wrapper
    assert row["result"] == "PASS" and report.exit_code == doctor.EXIT_VERIFIED, row
    err = capsys.readouterr().err
    assert "stays: server kept running after its input closed; the proxy stopped it" in err
    assert "may still be running" not in err
    assert _gone(json.loads(world.probe("stays").read_text())["pid"], within=1.0)
    assert live.EXIT_WAIT_S < elapsed < route_launch.ROUTE_S


def test_a_prompt_exit_prints_no_such_line(world, capsys):
    world.wire(world.user_file(), "prompt")
    report = world.run([("user", world.user_file())])
    assert report.outcome.per_wrapper[0]["result"] == "PASS"
    assert "kept running" not in capsys.readouterr().err


def test_a_silent_server_never_seen_is_gone_when_the_list_is_lost_at_full_size(
        world, monkeypatch, capsys):
    """The case that decided the design, at the production bounds: the process list is read
    once and then lost, the server never answers. The proxy's own teardown stops it, inside
    the route's 30 s, and the run does not claim it may still be running."""
    _table_lost_after(monkeypatch, 1)
    world.wire(world.user_file(), "dark", mode="silent")
    started = time.monotonic()
    report = world.run([("user", world.user_file())])
    elapsed = time.monotonic() - started
    [row] = report.outcome.per_wrapper
    assert row["result"] == "NOT_RUN", row
    assert elapsed <= route_launch.ROUTE_S, elapsed
    assert _gone(json.loads(world.probe("dark").read_text())["pid"], within=0.5), \
        "a server nobody could name was left running"
    err = capsys.readouterr().err
    assert "may still be running" not in err
    assert "no server process was seen below the proxy; the proxy stopped it" in err


def _slow_reads(monkeypatch, seconds):
    """Every read of the process list after the preflight takes `seconds` (or what its
    deadline leaves) and then yields nothing, as a slow `ps` or a long /proc walk does."""
    real = route_launch._process_table
    seen = {"n": 0}

    def table(window):
        seen["n"] += 1
        if seen["n"] == 1:
            return real(window)
        time.sleep(min(seconds, window.left()))
        return None

    monkeypatch.setattr(route_launch, "_process_table", table)


_HOLDER = "t10-pipe-holder-marker"

_SLOW_PEER = textwrap.dedent('''
    import json, subprocess, sys, time
    first = json.loads(sys.stdin.readline())
    # a descendant in its own session that keeps this process's output pipe open
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)  # t10-pipe-holder-marker"],
                     start_new_session=True)
    time.sleep(float(sys.argv[1]))
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": first["id"], "result": {
        "protocolVersion": "2024-11-05", "capabilities": {},
        "serverInfo": {"name": "slow", "version": "1"}}}) + "\\n")
    sys.stdout.flush()
    time.sleep(120)
''')


def test_a_peer_that_answers_late_and_then_stops_answering_ends_inside_the_deadline(
        tmp_path, monkeypatch):
    """The slow-peer measure at the `_drive_route` boundary: `initialize` is answered at
    17.8 s, every read of the process list is slow, nothing after that is answered, the peer
    ignores its closed input, and a descendant in its own session keeps the peer's output pipe
    open. FAIL, and the whole route, cleanup included (the reap of the killed peer and the
    join of its output reader too), ends inside `ROUTE_S`. A mutant that waits for the peer's
    exit without a limit never gets here; one that kills it with the unbudgeted
    `_Peer.kill` takes its 2 s join on top and ends past `ROUTE_S`."""
    peer = tmp_path / "peer.py"
    peer.write_text(_SLOW_PEER)
    _slow_reads(monkeypatch, 1.0)
    result = {}

    def run():
        clock = Clock(route_launch.ROUTE_S - route_launch.ROUTE_MARGIN_S)
        result["out"] = route_launch._drive_route([sys.executable, str(peer), "17.8"], None,
                                                  str(tmp_path), clock)

    started = time.monotonic()
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(route_launch.ROUTE_S + 10)
    elapsed = time.monotonic() - started
    try:
        assert not worker.is_alive(), "the route ran past its deadline"
        passed, checks, _ = result["out"]
        assert passed is False and checks["disconnect"] == "FAIL", result
        assert elapsed <= route_launch.ROUTE_S, elapsed
    finally:
        subprocess.run(["pkill", "-f", str(peer)], check=False)
        subprocess.run(["pkill", "-f", _HOLDER], check=False)


def test_a_failed_write_of_the_initialized_frame_is_a_fail(world, monkeypatch):
    """The frame is a step of the check: bytes that were not written are not a pass. The
    control is the first row of this file, the same route passing."""
    real = live._Peer.send

    def send(peer, message):
        if message.get("method") == "notifications/initialized":
            return b""
        return real(peer, message)

    monkeypatch.setattr(live._Peer, "send", send)
    world.wire(world.user_file(), "unsent")
    report = world.run([("user", world.user_file())])
    [row] = report.outcome.per_wrapper
    assert row["result"] == "FAIL" and report.exit_code == doctor.EXIT_FAILED, row


def test_a_read_of_the_process_list_ends_at_its_deadline(monkeypatch):
    """The /proc walk has no clock of its own: the deadline is checked between entries.
    Each entry costs 10 ms here, so 300 of them are 3 s; a 0.05 s deadline ends the read
    near 0.05 s and gives None (a read cut short is not an empty table)."""
    def slow_open(path, *args, **kwargs):
        time.sleep(0.01)
        raise OSError("gone")

    monkeypatch.setattr(Clock, "run", lambda *_a, **_k: None)  # `ps` cannot be run
    monkeypatch.setattr(route_launch.os, "listdir",
                        lambda path: [str(n) for n in range(100000, 100300)])
    monkeypatch.setattr(route_launch, "open", slow_open, raising=False)
    started = time.monotonic()
    table = route_launch._process_table(Clock(0.05))
    assert table is None and time.monotonic() - started < 0.5


# ── C532: one clock, enforced over the whole module, denied by default ────
#
# `route_launch.py` and `_deadline.py` are read as source. Nothing in them is exempt by
# position: a call, an import or a loop that the rules below do not allow is a failure, and
# the rules are proven on the real files, on in-memory mutations of them, and on a table of
# one-line shapes. What this proves (and no more): in `route_launch.py` every wait goes through
# a `Clock` or takes its time from `<clock>.take(...)`; in `_deadline.py` every blocking call
# takes its time from `self.take(...)`; a loop in a function that is given a clock checks it.
# What it does not prove: the time one system call takes (a `listdir`, a `read`, a pipe write),
# or that a check sits on every path of a loop; the probes below measure those.

_PEER_TIME_INDEX = {"wait": 0, "join": 0, "reply": 1}
_BLOCKING = {"communicate", "run", "call", "check_call", "check_output", "select", "recv",
             "recvfrom", "accept", "input", "acquire", "waitpid", "wait3", "wait4", "waitid",
             "system", "popen", "Popen", "sleep", "get", "readline", "readlines"}
_WATCHED = _BLOCKING | {"wait", "join", "reply", "kill"}
_DENIED_NAMES = {"getattr", "eval", "exec", "__import__", "partial", "compile"}
_CLOCK_METHODS = {"left", "spent", "take", "sub", "sleep", "wait", "join", "run"}
_ROUTE_IMPORTS = {"os", "shutil", "signal", "sys", "tempfile", "threading", "time"}
_DEADLINE_IMPORTS = {"subprocess", "time"}
_DEADLINE_TIMED = {"sleep": 0, "wait": 0, "join": 0, "communicate": 1}


def _is_clock_ref(node, names, attrs):
    return (isinstance(node, ast.Name) and node.id in names) \
        or (isinstance(node, ast.Attribute) and node.attr in attrs)


def _makes_clock(value, names, attrs):
    if not isinstance(value, ast.Call):
        return False
    if isinstance(value.func, ast.Name):
        return value.func.id == "Clock"
    return isinstance(value.func, ast.Attribute) and value.func.attr == "sub" \
        and _is_clock_ref(value.func.value, names, attrs)


def _clock_names(fn, attrs):
    own = {a.arg for a in fn.args.args + fn.args.kwonlyargs if a.arg in {"clock", "window"}}
    names = set(own)
    for _ in range(3):
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name) \
                    and _makes_clock(node.value, names, attrs):
                names.add(node.targets[0].id)
    return own, names


def _is_take(node, names, attrs):
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
        and node.func.attr == "take" and _is_clock_ref(node.func.value, names, attrs)


def _time_argument(call, index):
    for keyword in call.keywords:
        if keyword.arg in {"timeout", "limit_s"}:
            return keyword.value
    return call.args[index] if len(call.args) > index else None


def _text_join(call):
    receiver = call.func.value
    return isinstance(receiver, ast.Constant) \
        or (isinstance(receiver, ast.Attribute) and receiver.attr == "path")


def _route_call(call, names, attrs, found):
    func = call.func
    if isinstance(func, ast.Name):
        if func.id in _DENIED_NAMES:
            found.append((call.lineno, f"{func.id}() hides what is called"))
        if func.id in _BLOCKING:
            found.append((call.lineno, f"{func.id}() blocks"))
        if func.id == "_Peer":
            if not any(_is_clock_ref(a, names, attrs) for a in call.args + [k.value for k in call.keywords]):
                found.append((call.lineno, "_Peer( without a clock"))
        return
    if not isinstance(func, ast.Attribute):
        found.append((call.lineno, "a call through an expression"))
        return
    attr = func.attr
    if _is_clock_ref(func.value, names, attrs):
        if attr not in _CLOCK_METHODS:
            found.append((call.lineno, f"clock.{attr} is not a clock primitive"))
        return
    if attr in _DENIED_NAMES:
        found.append((call.lineno, f".{attr}() hides what is called"))
    if attr == "_Peer" or attr == "kill":
        if not any(_is_clock_ref(a, names, attrs) for a in call.args + [k.value for k in call.keywords]):
            found.append((call.lineno, f"{attr}( without a clock"))
        return
    if attr == "get":
        plain = call.args and not call.keywords \
            and not (isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, bool))
        if not plain:
            found.append((call.lineno, "a get() that can wait"))
        return
    if attr == "join" and _text_join(call):
        return
    if attr in _PEER_TIME_INDEX:
        given = _time_argument(call, _PEER_TIME_INDEX[attr])
        if given is None or not _is_take(given, names, attrs):
            found.append((call.lineno, f".{attr}() is not given <clock>.take(...)"))
        return
    if attr in _BLOCKING:
        found.append((call.lineno, f".{attr}() is not a clock primitive"))


def _own_nodes(loop):
    """The nodes of a loop's test and body, not those of a loop inside it: each loop checks
    the clock itself, so a check in an inner loop does not cover the outer one."""
    pending = [loop.test] if isinstance(loop, ast.While) else [loop.iter]
    pending += list(loop.body)
    while pending:
        node = pending.pop()
        yield node
        if not isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            pending.extend(ast.iter_child_nodes(node))


def _walk(node, names, attrs, state, found):
    """Pre-order visit. `state` has the ids of attribute nodes that are being called and the
    loops found in functions that were not given a clock."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        own, names = _clock_names(node, attrs)
        for sub in ast.walk(node):
            if isinstance(sub, ast.Assign) and len(sub.targets) == 1 \
                    and isinstance(sub.targets[0], ast.Name) and sub.targets[0].id in own \
                    and not _makes_clock(sub.value, names, attrs):
                found.append((sub.lineno, "a clock name is bound to something else"))
        state["stack"].append((node.name, bool(own)))
    given = bool(state["stack"]) and state["stack"][-1][1]
    if isinstance(node, ast.Call):
        state["called"].add(id(node.func))
        _route_call(node, names, attrs, found)
    if isinstance(node, ast.Attribute) and node.attr in _WATCHED \
            and id(node) not in state["called"] and not isinstance(node.ctx, ast.Store):
        found.append((node.lineno, f".{node.attr} is used without being called"))
    if isinstance(node, ast.Attribute) and _is_clock_ref(node.value, names, attrs) \
            and id(node) not in state["called"]:
        found.append((node.lineno, f"clock.{node.attr} is written or passed on without a call"))
    if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
        test = node.test if isinstance(node, ast.While) else node.iter
        if given:
            checked = any(isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
                          and c.func.attr == "spent" and _is_clock_ref(c.func.value, names, attrs)
                          for c in _own_nodes(node))
            if not checked:
                found.append((node.lineno, "a loop in a function with a clock never checks it"))
        else:
            state["clockless"].append((".".join(n for n, _ in state["stack"]), ast.unparse(test)))
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
        if given:
            found.append((node.lineno, "a comprehension in a function with a clock"))
        else:
            for generator in node.generators:
                state["clockless"].append((".".join(n for n, _ in state["stack"]),
                                           ast.unparse(generator.iter)))
    for child in ast.iter_child_nodes(node):
        _walk(child, names, attrs, state, found)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        state["stack"].pop()


def _route_imports(tree, found):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in _ROUTE_IMPORTS:
                    found.append((node.lineno, f"import {alias.name}"))
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module != "__future__":
            found.append((node.lineno, f"from {node.module} import ..."))


# The loops in `route_launch.py` that sit in a function with no clock, pinned with what each
# one runs over. Another loop there, or a changed one, fails until it is read and added here.
_CLOCKLESS_LOOPS = [
    ("__enter__", "(signal.SIGTERM, signal.SIGHUP, signal.SIGINT)"),
    ("__exit__", "self._previous.items()"),
    ("_build", "[command, *args]"),
    ("_build", "own.items() if isinstance(own, dict) else ()"),
    ("_kill_all", "groups"),
    ("_shown", "str(text)[:limit]"),
]


def _route_violations(source):
    """[(line, why)] for `route_launch.py`-shaped source."""
    tree = ast.parse(source)
    attrs = {t.attr for n in ast.walk(tree) if isinstance(n, ast.Assign)
             for t in n.targets if isinstance(t, ast.Attribute)
             and _makes_clock(n.value, set(), set())}
    found, state = [], {"called": set(), "stack": [], "clockless": []}
    _route_imports(tree, found)
    _walk(tree, set(), attrs, state, found)
    for pinned in state["clockless"]:
        if state["clockless"].count(pinned) > _CLOCKLESS_LOOPS.count(pinned):
            found.append((0, f"a loop with no clock: {pinned}"))
    return found, state["clockless"]


def _deadline_violations(source):
    tree = ast.parse(source)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in _DEADLINE_IMPORTS:
                    found.append((node.lineno, f"import {alias.name}"))
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module != "__future__":
            found.append((node.lineno, f"from {node.module} import ..."))
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While, ast.ListComp, ast.SetComp,
                             ast.DictComp, ast.GeneratorExp)):
            found.append((node.lineno, "a loop in the file that holds the blocking calls"))
    called = set()
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        taken = {}
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                ok = isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) \
                    and node.value.func.attr == "take" \
                    and isinstance(node.value.func.value, ast.Name) \
                    and node.value.func.value.id == "self"
                taken[name] = taken.get(name, True) and ok
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            called.add(id(node.func))
            func = node.func
            if isinstance(func, ast.Name):
                if func.id in _DENIED_NAMES | _BLOCKING:
                    found.append((node.lineno, f"{func.id}()"))
                continue
            if not isinstance(func, ast.Attribute):
                found.append((node.lineno, "a call through an expression"))
                continue
            if isinstance(func.value, ast.Name) and func.value.id == "self":
                continue
            if func.attr in _DENIED_NAMES:
                found.append((node.lineno, f".{func.attr}()"))
            if isinstance(func.value, ast.Name) and func.value.id == "subprocess":
                if func.attr != "Popen":
                    found.append((node.lineno, f"subprocess.{func.attr}"))
                continue
            if func.attr in _DEADLINE_TIMED and not (func.attr == "join" and _text_join(node)):
                given = _time_argument(node, _DEADLINE_TIMED[func.attr])
                if not (isinstance(given, ast.Name) and taken.get(given.id)):
                    found.append((node.lineno, f".{func.attr}() is not given a local from self.take()"))
            elif func.attr in _BLOCKING - {"Popen"}:
                found.append((node.lineno, f".{func.attr}() is not allowed here"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _WATCHED \
                and id(node) not in called and not isinstance(node.ctx, ast.Store):
            found.append((node.lineno, f".{node.attr} is used without being called"))
    return found


def _sources():
    return (Path(route_launch.__file__).read_text(),
            Path(sys.modules[Clock.__module__].__file__).read_text())


def test_the_route_module_is_clean_under_the_deny_by_default_rules():
    route, deadline = _sources()
    assert _route_violations(route)[0] == []
    assert _deadline_violations(deadline) == []


def test_the_pinned_loops_without_a_clock_are_exactly_the_ones_in_the_module():
    """A pin that no longer matches a loop is stale and goes; a loop without a pin fails the
    test above. The loops are over a fixed tuple, a dict of handlers, the user's own
    environment, a name filter, or the groups already read: none of them waits."""
    found = _route_violations(_sources()[0])[1]
    assert sorted(found) == sorted(_CLOCKLESS_LOOPS)


def test_the_clock_takes_its_time_from_its_own_end():
    take = [n for n in ast.walk(ast.parse(_sources()[1]))
            if isinstance(n, ast.FunctionDef) and n.name == "take"][0]
    assert ast.unparse(take.body[-1]) == "return max(0.0, min(bound, self.left() - reserve))"


def _mutate(source, old, new):
    assert source.count(old) >= 1, f"the mutation anchor is gone: {old!r}"
    return source.replace(old, new, 1)


_ROUTE_MUTATIONS = [
    ("peer.wait(None)", "self.peer.wait(clock.take(PROXY_TEARDOWN_S))", "self.peer.wait(None)"),
    ("peer.wait(literal)", "self.peer.wait(clock.take(PROXY_TEARDOWN_S))", "self.peer.wait(8.0)"),
    ("peer.wait(clock.left())", "peer.wait(clock.take(PROXY_TEARDOWN_S, _live.GROUP_GONE_S))",
     "peer.wait(clock.left())"),
    ("reply(constant)", "peer.reply(1, window.take(WATCH_STEP_S))", "peer.reply(1, WATCH_STEP_S)"),
    ("time.sleep in the wait loop", "gone.sleep(NAP_S)", "time.sleep(NAP_S)"),
    ("import subprocess", "import threading\n", "import threading\nimport subprocess\n"),
    ("import queue", "import threading\n", "import threading\nimport queue\n"),
    ("from time import sleep", "import time\n", "import time\nfrom time import sleep\n"),
    ("/proc loop check removed",
     "            if window.spent():\n                return None\n            if not name.isdigit():",
     "            if not name.isdigit():"),
    ("ps row check removed",
     "        for line in done[1].splitlines():\n            if window.spent():\n                return None\n",
     "        for line in done[1].splitlines():\n"),
    ("graph walk check removed", "    while todo:\n        if window.spent():\n            return groups, True\n",
     "    while todo:\n"),
    ("alive loop check removed", " or (unlooked and clock.spent())", ""),
    ("_Peer without the clock", "_live._Peer(argv, env, cwd, clock)", "_live._Peer(argv, env, cwd)"),
    ("kill without the clock", "self.peer.kill(clock)", "self.peer.kill()"),
    ("getattr hides a wait", "        proxy = self.peer.proc.pid\n",
     "        proxy = self.peer.proc.pid\n        getattr(self.peer, 'wait')(None)\n"),
    ("alias of a wait", "        proxy = self.peer.proc.pid\n",
     "        proxy = self.peer.proc.pid\n        waiter = self.peer.wait\n"),
    ("communicate outside the clock", "        proxy = self.peer.proc.pid\n",
     "        proxy = self.peer.proc.pid\n        self.peer.proc.communicate(None, 2.0)\n"),
    ("a new loop with no check", "def _discovery_works() -> bool:",
     "def _spin(clock):\n    for _ in range(10 ** 9):\n        pass\n\n\ndef _discovery_works() -> bool:"),
    ("a comprehension where a clock is given", "    unlooked = len(groups)\n",
     "    unlooked = len([g for g in groups])\n"),
    ("a second loop where there is no clock", "        _live._kill_group(group)\n",
     "        _live._kill_group(group)\n    for extra in groups:\n        pass\n"),
]

_DEADLINE_MUTATIONS = [
    ("wait limit not taken", "        limit = self.take(bound)\n        try:\n            return proc.wait(",
     "        limit = bound\n        try:\n            return proc.wait("),
    ("wait with no limit", "proc.wait(timeout=limit)", "proc.wait()"),
    ("join with no limit", "thread.join(limit)", "thread.join()"),
    ("sleep with a literal", "time.sleep(pause)", "time.sleep(0.5)"),
    ("communicate with no limit", "proc.communicate(timeout=limit)", "proc.communicate()"),
    ("communicate positional literal", "proc.communicate(timeout=limit)", "proc.communicate(None, 30.0)"),
    ("subprocess.run", "subprocess.Popen(argv", "subprocess.run(argv"),
    ("import select", "import time\n", "import time\nimport select\n"),
    ("a loop in the blocking file", "        return proc.returncode, output",
     "        for _ in output:\n            pass\n        return proc.returncode, output"),
    ("the reap with no limit", "self.wait(proc, REAP_S)", "proc.wait()"),
]


def test_each_mutation_of_the_real_source_is_refused_by_the_rules():
    route, deadline = _sources()
    missed = []
    for label, old, new in _ROUTE_MUTATIONS:
        if not _route_violations(_mutate(route, old, new))[0]:
            missed.append(label)
    for label, old, new in _DEADLINE_MUTATIONS:
        if not _deadline_violations(_mutate(deadline, old, new)):
            missed.append(label)
    assert not missed, f"the rules let these through: {missed}"
    assert len(_ROUTE_MUTATIONS) + len(_DEADLINE_MUTATIONS) >= 28


def _in_function(*lines):
    return "def f(clock, peer, q, d, x, argv, env, cwd, rows):\n" + "".join(
        "    " + line + "\n" for text in lines for line in text.splitlines())


_REFUSED_SHAPES = [
    "peer.wait(None)", "peer.wait()", "peer.wait(2.0)", "peer.wait(timeout=2.0)",
    "peer.wait(max(0, clock.left()))", "peer.reply(1, 0.25)", "peer.reply(1)", "x.join()",
    "x.join(2)", "time.sleep(0.05)", "q.get()", "q.get(timeout=1)", "q.get(True, 5)",
    "x.communicate()", "x.communicate(None, 2.0)", "x.communicate(timeout=clock.take(1))",
    "subprocess.run(x)", "os.waitpid(1, 0)", "getattr(peer, 'wait')(None)", "w = peer.wait",
    "functools.partial(peer.wait, None)()", "peer.kill()", "_live._Peer(argv, env, cwd)",
    "for r in rows:\n    pass", "while True:\n    pass", "y = [r for r in rows]",
    "select.select([x], [], [], 1)", "x.acquire()", "os.popen('ps')", "clock.left = None",
    "clock = peer", "clock.pending()", "peer.send(1).wait(3)", "(lambda: peer.wait(None))()",
]

_ACCEPTED_SHAPES = [
    "clock.sleep(1)", "peer.wait(clock.take(2.0))", "peer.reply(1, clock.take(1, 2))",
    "d.get('a')", "', '.join(x)", "os.path.join(x, x)", "peer.kill(clock)",
    "_live._Peer(argv, env, cwd, clock)",
    "for r in rows:\n    if clock.spent():\n        break",
    "inner = clock.sub(1.0)\ninner.sleep(0.1)\npeer.wait(inner.take(1))",
    "while not clock.spent():\n    clock.sleep(0.1)",
]


def test_the_rules_refuse_each_blocking_shape_and_accept_the_clock_ones():
    leaked = [s for s in _REFUSED_SHAPES if not _route_violations(_in_function(s))[0]]
    assert not leaked, f"not refused: {leaked}"
    refused = [s for s in _ACCEPTED_SHAPES if _route_violations(_in_function(s))[0]]
    assert not refused, f"refused although they go through the clock: {refused}"
    for source in ("import subprocess", "from time import sleep", "from subprocess import run",
                   "import queue", "import select", "import socket", "import asyncio"):
        assert _route_violations(source)[0], source
    assert len(_REFUSED_SHAPES) + len(_ACCEPTED_SHAPES) >= 40


def test_every_constant_named_for_seconds_is_a_positive_number():
    names = [n for n in dir(route_launch) if n.endswith("_S") and not n.startswith("_")]
    assert len(names) >= 8
    for name in names:
        value = getattr(route_launch, name)
        assert isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0, name


# ── C532: runtime probes (what the source rules cannot show) ─────────────

class _Ticking:
    """A clock source that moves 10 ms every time it is read, and counts the reads."""

    def __init__(self, step=0.01):
        self.at, self.step, self.reads = 1000.0, step, 0

    def __call__(self):
        self.reads += 1
        self.at += self.step
        return self.at


def test_a_clock_never_waits_longer_than_its_own_end_or_the_bound():
    now = _Ticking(step=0.0)
    clock = Clock(5.0, now=now)
    assert clock.take(2.0) == 2.0 and clock.take(9.0) == 5.0 and clock.take(9.0, 4.0) == 1.0
    assert clock.take(9.0, 99.0) == 0.0 and not clock.spent()
    child = clock.sub(1.0)
    now.at += 0.4
    assert abs(child.left() - 0.6) < 1e-9 and abs(clock.left() - 4.6) < 1e-9
    now.at += 0.7
    assert child.spent() and child.take(3.0) == 0.0 and not clock.spent()
    assert Clock(0.0, now=now).sub(30.0).spent()


def test_a_process_table_of_100_rows_read_on_a_0_05_second_clock_stops_after_a_few_rows(
        monkeypatch):
    """A fake clock moves 10 ms per read. A 100-row `ps` answer on a 0.05 s clock is cut
    short near row 5 and is None, not a table of 5; with enough time the same answer is the
    whole table. A loop that never looked at the clock would read all 100 rows."""
    text = "".join(f"{1000 + n} {999 + n} {1000 + n}\n" for n in range(100))
    monkeypatch.setattr(Clock, "run", lambda *_a, **_k: (0, text))
    short = _Ticking()
    assert route_launch._process_table(Clock(0.05, now=short)) is None
    assert short.reads < 20, short.reads
    full = route_launch._process_table(Clock(1000.0, now=_Ticking()))
    assert len(full) == 100


def test_a_walk_over_100_rows_on_a_0_05_second_clock_says_it_is_cut_short():
    table = {1000 + n: (999 + n, 5000 + n) for n in range(100)}
    short = _Ticking()
    groups, truncated = route_launch._descendant_groups(
        999, Clock(0.05, now=short), table=table)
    assert truncated is True and short.reads < 20 and len(groups) < 100, (short.reads, groups)
    groups, truncated = route_launch._descendant_groups(
        999, Clock(1000.0, now=_Ticking()), table=table)
    assert truncated is False and len(groups) == 100


def test_a_stand_in_for_ps_that_will_not_stop_is_given_up_on_at_its_bound_plus_the_reap(
        monkeypatch):
    """The standard library's `run` waits without a limit after it kills a command that ran
    over. `Clock.run` kills it itself and waits `REAP_S` at most, so a command that does not
    die still returns by `bound + REAP_S`."""
    waits = []

    class Stubborn:
        stdout = types.SimpleNamespace(close=lambda: None)
        returncode = None

        def communicate(self, timeout):
            time.sleep(timeout)
            raise subprocess.TimeoutExpired("ps", timeout)

        def kill(self):
            pass

        def wait(self, timeout):
            waits.append(timeout)
            time.sleep(timeout)
            raise subprocess.TimeoutExpired("ps", timeout)

    import sunglasses.proxy._deadline as deadline
    monkeypatch.setattr(deadline.subprocess, "Popen", lambda *a, **k: Stubborn())
    started = time.monotonic()
    assert Clock(30.0).run(["ps"], 0.3, {}) is None
    took = time.monotonic() - started
    assert waits == [REAP_S] and took <= 0.3 + REAP_S + 0.5, (waits, took)
    # the same through a clock that has almost nothing left: the reap is cut to that
    waits.clear()
    started = time.monotonic()
    assert Clock(0.4).run(["ps"], 5.0, {}) is None
    assert waits and waits[0] <= 0.05 and time.monotonic() - started < 0.7, waits


def test_a_real_command_that_ignores_term_is_killed_and_run_returns_at_its_bound():
    marker = "t10-c532-stubborn-61"
    started = time.monotonic()
    out = Clock(30.0).run(["sh", "-c", f"trap '' TERM INT; sleep {marker[-2:]}.7"], 0.3, {})
    try:
        assert out is None and time.monotonic() - started < 0.3 + REAP_S + 0.5
    finally:
        subprocess.run(["pkill", "-f", f"sleep {marker[-2:]}.7"], check=False)
    ok = Clock(30.0).run(["sh", "-c", "echo hi"], 5.0, {"PATH": os.defpath})
    assert ok == (0, "hi\n")
    assert Clock(30.0).run(["no-such-program-t10"], 1.0, {}) is None


def test_a_peer_whose_reader_started_and_whose_start_then_failed_is_cleaned_up_inside_the_clock(
        tmp_path, monkeypatch):
    """Partial construction: the process exists, the reader thread runs, `start()` raises,
    and a descendant in its own session holds the output pipe open. The reader cannot end,
    so its join is the wait that must be cut. After the failure, the cleanup takes what is
    left of the 1.2 s clock; the unbudgeted join alone is `PUMP_JOIN_S` (2 s)."""
    pidfile = tmp_path / "peer.pid"
    script = tmp_path / "peer.py"
    script.write_text(textwrap.dedent(f'''
        import os, subprocess, sys, time
        subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)  # {_HOLDER}"],
                         start_new_session=True)
        open({str(pidfile)!r}, "w").write(str(os.getpid()))
        time.sleep(120)
    '''))
    seen = {}

    class OddThread(threading.Thread):
        def start(self):
            super().start()
            # let the peer start its descendant, then fail
            end = time.monotonic() + 5
            while time.monotonic() < end and not pidfile.exists():
                time.sleep(0.02)
            time.sleep(0.2)
            seen["holder"] = subprocess.run(["pgrep", "-f", _HOLDER],
                                            capture_output=True).returncode == 0
            seen["raised"] = time.monotonic()
            raise RuntimeError("cannot start another thread")

    monkeypatch.setattr(live, "threading", types.SimpleNamespace(Thread=OddThread))
    try:
        with pytest.raises(live._CouldNotStart):
            route_launch._Route([sys.executable, str(script)], None, str(tmp_path), Clock(1.2))
        after = time.monotonic() - seen["raised"]
        assert seen["holder"], "the pipe-holding descendant was not there"
        assert after < live.PUMP_JOIN_S - 0.3, after
        assert _gone(int(pidfile.read_text()), within=3.0), "the peer was left running"
    finally:
        subprocess.run(["pkill", "-f", _HOLDER], check=False)
