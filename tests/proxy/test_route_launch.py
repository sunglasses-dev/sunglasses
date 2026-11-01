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
    def no_ps(*_a, **_k):
        raise OSError("no ps here")

    monkeypatch.setattr(route_launch, "subprocess",
                        types.SimpleNamespace(run=no_ps, SubprocessError=subprocess.SubprocessError))
    assert os.getpid() in route_launch._process_table(3.0)
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

    def table(limit_s):
        seen["n"] += 1
        if seen["n"] == 1:
            return real(limit_s)
        time.sleep(min(seconds, limit_s))
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
        budget = live._Budget(route_launch.ROUTE_S - route_launch.ROUTE_MARGIN_S)
        result["out"] = route_launch._drive_route([sys.executable, str(peer), "17.8"], None,
                                                  str(tmp_path), budget)

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
    def no_ps(*args, **kwargs):
        raise OSError("no ps")

    def slow_open(path, *args, **kwargs):
        time.sleep(0.01)
        raise OSError("gone")

    monkeypatch.setattr(route_launch.subprocess, "run", no_ps)
    monkeypatch.setattr(route_launch.os, "listdir",
                        lambda path: [str(n) for n in range(100000, 100300)])
    monkeypatch.setattr(route_launch, "open", slow_open, raising=False)
    started = time.monotonic()
    table = route_launch._process_table(0.05)
    assert table is None and time.monotonic() - started < 0.5


# ── review r4: one clock, checked in the source ─────────────────────────

_TIMED_METHODS = {"wait", "join", "sleep", "reply"}


def _calls_in(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def _is_cap(node):
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
        and node.func.id in {"_cap"}


def _timing_arguments(call):
    """(label, expression) for every argument of `call` that carries a time."""
    name = call.func.attr if isinstance(call.func, ast.Attribute) else \
        call.func.id if isinstance(call.func, ast.Name) else ""
    out = []
    receiver = call.func.value if isinstance(call.func, ast.Attribute) else None
    # str.join and os.path.join are not waits.
    text_join = name == "join" and (isinstance(receiver, ast.Constant)
                                    or (isinstance(receiver, ast.Attribute)
                                        and receiver.attr == "path"))
    if name in _TIMED_METHODS and not text_join:
        index = 1 if name == "reply" else 0
        if len(call.args) > index:
            out.append((name, call.args[index]))
        else:
            out.append((name, None))  # no timeout at all: wait(), join(), get()
    if name in {"_process_table", "_descendant_groups"}:
        index = 0 if name == "_process_table" else 1
        out.append((name, call.args[index] if len(call.args) > index else None))
    for keyword in call.keywords:
        if keyword.arg in {"timeout", "limit_s"}:
            out.append((keyword.arg, keyword.value))
    return out


def _module_tree():
    return ast.parse(Path(route_launch.__file__).read_text())


def test_every_wait_in_the_route_module_is_cut_by_the_one_helper():
    """R25.5 (1): the module hands no time of its own to a wait, join, reap, sleep or read.
    Every one is `_cap(...)` (or the bound of a function that is itself given one), so none
    can be left off the route's deadline. `wait(None)`, a bare `join()` and a literal fail."""
    tree = _module_tree()
    inside = {"_cap": None, "_process_table": None}
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef) and fn.name in inside:
            inside[fn.name] = {id(n) for n in ast.walk(fn)}
    checked, bad = 0, []
    for call in _calls_in(tree):
        for label, expression in _timing_arguments(call):
            owner = [n for n, ids in inside.items() if ids and id(call) in ids]
            if owner:
                continue  # the helper itself, and the one read that is given limit_s
            checked += 1
            ok = expression is not None and (_is_cap(expression)
                                             or (isinstance(expression, ast.Name)
                                                 and expression.id == "limit_s"))
            if not ok:
                bad.append((call.lineno, label, ast.dump(expression) if expression else None))
    assert checked >= 10, f"the check looked at only {checked} timed calls"
    assert not bad, f"a timed call is not cut by _cap: {bad}"


def test_the_one_helper_takes_its_time_from_a_budget():
    """`_cap` is the only place a bound meets the clock: it reads `budget.left()`."""
    tree = _module_tree()
    [cap] = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_cap"]
    text = ast.unparse(cap)
    assert "budget.left()" in text and "max(0.0" in text and "min(bound" in text


def test_the_static_check_fails_on_the_unbudgeted_shapes():
    """The check is not blind: each of the shapes it exists for is found."""
    for source in ("peer.wait(None)", "reader.join()", "peer.wait(2.0)", "time.sleep(0.05)",
                   "peer.reply(1, 0.25)", "_process_table(3.0)",
                   "subprocess.run(x, timeout=3)", "q.get(timeout=1)",
                   "reader.join(2)"):
        [call] = [c for c in _calls_in(ast.parse(source)) if _timing_arguments(c)][:1]
        [(label, expression)] = _timing_arguments(call)[:1]
        assert expression is None or not _is_cap(expression), source
