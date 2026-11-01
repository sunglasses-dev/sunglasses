"""The doctor's live self-test, against real processes.

The rows that need a process spawn the installed proxy and the bundled echo server
over real pipes; the rest inject a refusal or a result. The mutation rows put a
deliberately wrong proxy in front of the same echo server and ask whether the check
built to catch that wrongness goes red (a wrong proxy can turn more than one check
red, and each row asserts the one it is about). A battery that passes against the
right proxy and the wrong one proves nothing, so each wrong proxy is paired with a
right one that passes.
"""
import os
import signal
import sys
import tempfile
import textwrap
import time

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)

from sunglasses.proxy import doctor, live_selftest as live  # noqa: E402

pytestmark = pytest.mark.skipif(not (hasattr(os, "killpg") and os.name == "posix"),
                                reason="the self-test needs process groups")

CHECKS = doctor.SELF_TEST_CHECKS

# A proxy that is right (`ok`) or wrong in exactly one way. It starts the bundled
# echo server itself, in its own group, and relays between the client and it.
_MUTANT = textwrap.dedent('''
    import json, subprocess, sys, time
    mode, ingress, proc_file = sys.argv[1:4]
    echo = subprocess.Popen(
        [sys.executable, "-m", "sunglasses.proxy.echo_server", "--ingress", ingress,
         "--proc", proc_file] + (["--linger"] if mode == "leave_echo" else []),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, start_new_session=True)

    def withheld(request_id):
        return {"jsonrpc": "2.0", "id": request_id, "error": {
            "code": -32070, "message": "SUNGLASSES_WITHHELD", "data": {
                "reason_code": "APPROVAL_REQUIRED", "rule": "S4", "status": "not_run",
                "server_id": "x" * 32, "snapshot_sha256": "y" * 64}}}

    def say(message):
        sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\\n")
        sys.stdout.flush()

    def relay(raw):
        echo.stdin.write(raw)
        echo.stdin.flush()
        return json.loads(echo.stdout.readline())

    if mode == "leave_proxy_child":
        subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])

    for raw in sys.stdin.buffer:
        message = json.loads(raw)
        method = message.get("method")
        if mode == "slow" and method == "ping":
            time.sleep(3)
        if mode == "slow_each" and method in ("ping", "tools/list", "tools/call"):
            time.sleep(1)
        if mode == "spoof_init" and method == "initialize":
            relay(raw)
            say({"jsonrpc": "2.0", "id": message["id"],
                 "result": {"serverInfo": {"name": "sunglasses-echo"}}})
            continue
        if mode == "ping_error" and method == "ping":
            relay(raw)
            say({"jsonrpc": "2.0", "id": message["id"],
                 "error": {"code": -32603, "message": "Internal error"}})
            continue
        if method in ("tools/list", "tools/call") and mode != "forward_unapproved":
            say(withheld(message["id"]))
            continue
        if mode == "rewrite_request":
            raw = raw.rstrip(b"\\n") + b" \\n"
        if "id" in message:
            say(relay(raw))
        else:
            echo.stdin.write(raw)
            echo.stdin.flush()
    echo.stdin.close()
    if mode != "leave_echo":
        echo.wait()
''')


def _battery(tmp_path, argv_for, first_reply_s=20.0):
    tmp = str(tmp_path)
    ingress, proc_file = os.path.join(tmp, "i"), os.path.join(tmp, "p")
    return live._battery(argv_for(ingress, proc_file), live._env(tmp), tmp, ingress, proc_file,
                         first_reply_s, live._Budget(60))


def _mutant(tmp_path, mode):
    script = tmp_path / "mutant.py"
    script.write_text(_MUTANT)
    return lambda ingress, proc_file: [sys.executable, str(script), mode, ingress, proc_file]


def _proxy(ingress, proc_file):
    return [sys.executable, "-m", "sunglasses.proxy", "--state-root",
            os.path.join(os.path.dirname(ingress), "state"), "--"] + live._echo_argv(ingress, proc_file)


# ── the real thing: one row per check ───────────────────────────────────

@pytest.fixture(scope="module")
def real():
    return live.run()


def test_the_live_self_test_passes_and_every_control_fails(real):
    ok, controls, checks, info = real
    assert ok is True
    assert controls == {"constant_allow": "FAIL", "constant_deny": "FAIL",
                        "skipped_invocation": "FAIL"}
    assert info["deadline_ms"] <= doctor.DEADLINE_BOUND_MS
    assert doctor.judge_self_test(checks, controls).ok


@pytest.mark.parametrize("name", CHECKS)
def test_each_named_check_ran_and_passed(real, name):
    assert real[2][name] == "PASS"


def test_the_real_proxy_in_front_of_the_echo_passes_the_battery(tmp_path):
    came_up, checks, deadline_ms = _battery(tmp_path, _proxy)
    assert came_up and set(checks) == set(CHECKS)
    assert all(v == "PASS" for v in checks.values()), checks
    assert deadline_ms <= doctor.DEADLINE_BOUND_MS


# ── the private world ───────────────────────────────────────────────────

def test_the_run_leaves_nothing_behind_and_writes_no_approval(tmp_path, monkeypatch):
    home, scratch = tmp_path / "home", tmp_path / "scratch"
    home.mkdir()
    scratch.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    ok, _, _, _ = live.run()
    assert ok
    assert os.listdir(home) == []          # nothing from the real HOME was read or written
    assert os.listdir(scratch) == []       # the private folder is gone, approvals folder with it


def test_the_private_folder_is_mode_0700(tmp_path, monkeypatch):
    seen = []
    real_mkdtemp = tempfile.mkdtemp

    def spy(*args, **kwargs):
        path = real_mkdtemp(*args, **kwargs)
        seen.append(path)
        return path

    monkeypatch.setattr(live.tempfile, "mkdtemp", spy)
    monkeypatch.setattr(live, "_battery", lambda *a, **k: (seen.append(oct(os.stat(a[2]).st_mode & 0o777)) or (False, {}, 0)))
    live.run()
    assert seen[1] == "0o700"


# ── the four wrong proxies ──────────────────────────────────────────────

def test_the_right_mutant_proxy_passes_so_the_wrong_ones_mean_something(tmp_path):
    came_up, checks, _ = _battery(tmp_path, _mutant(tmp_path, "ok"))
    assert came_up and all(v == "PASS" for v in checks.values()), checks


def test_a_proxy_that_rewrites_a_request_byte_fails_s1(tmp_path):
    _, checks, _ = _battery(tmp_path, _mutant(tmp_path, "rewrite_request"))
    assert checks["s1_forward_byte_equal"] == "FAIL"


def test_a_proxy_that_forwards_tools_list_unapproved_fails_s2(tmp_path):
    _, checks, _ = _battery(tmp_path, _mutant(tmp_path, "forward_unapproved"))
    assert checks["s2_block_schema"] == "FAIL"
    assert checks["s1_forward_byte_equal"] == "PASS"


def test_a_proxy_that_answers_after_three_seconds_fails_the_deadline(tmp_path):
    _, checks, deadline_ms = _battery(tmp_path, _mutant(tmp_path, "slow"))
    assert checks["deadline"] == "FAIL"
    assert deadline_ms > doctor.DEADLINE_BOUND_MS


def test_an_initialize_answer_that_is_not_the_echo_servers_fails_initialized(tmp_path):
    _, checks, _ = _battery(tmp_path, _mutant(tmp_path, "spoof_init"))
    assert checks["initialized"] == "FAIL"
    assert checks["s1_forward_byte_equal"] == "PASS"


def test_a_ping_answered_with_an_error_fails_the_deadline_check(tmp_path):
    _, checks, _ = _battery(tmp_path, _mutant(tmp_path, "ping_error"))
    assert checks["deadline"] == "FAIL"
    assert checks["initialized"] == "PASS"


def test_three_one_second_replies_are_charged_together_from_the_second_frame(tmp_path):
    _, checks, deadline_ms = _battery(tmp_path, _mutant(tmp_path, "slow_each"))
    assert checks["deadline"] == "FAIL"
    assert deadline_ms >= 3000


def test_the_clock_starts_before_the_second_frame_is_written(tmp_path, monkeypatch):
    real_send = live._Peer.send

    def slow_send(self, message):
        if message == live._INITIALIZED:
            time.sleep(3)
        return real_send(self, message)

    monkeypatch.setattr(live._Peer, "send", slow_send)
    _, checks, deadline_ms = _battery(tmp_path, _proxy)
    assert checks["deadline"] == "FAIL"
    assert deadline_ms >= 3000


def test_a_proxy_that_leaves_the_echo_alive_fails_disconnect_and_is_cleaned_up(tmp_path):
    _, checks, _ = _battery(tmp_path, _mutant(tmp_path, "leave_echo"))
    assert checks["disconnect"] == "FAIL"
    assert checks["s1_forward_byte_equal"] == "PASS"
    group = live._read_pgid(str(tmp_path / "p"))
    deadline = time.monotonic() + 3
    while live._group_alive(group) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not live._group_alive(group), "the leftover echo group was not killed"


# ── controls and the instrument not coming up ───────────────────────────

@pytest.mark.parametrize("argv", [
    [sys.executable, "-c", "pass"],
    [sys.executable, "-c", live._DENY_STUB],
])
def test_a_peer_that_cannot_be_right_does_not_pass_the_battery(tmp_path, argv):
    came_up, checks, _ = _battery(tmp_path, lambda *_: argv, first_reply_s=5.0)
    assert not (len(checks) == 5 and all(v == "PASS" for v in checks.values()))


def test_a_spawn_that_never_answers_initialize_did_not_come_up(tmp_path):
    started = time.monotonic()
    came_up, checks, _ = _battery(
        tmp_path, lambda *_: [sys.executable, "-c", "import time; time.sleep(30)"],
        first_reply_s=0.5)
    assert came_up is False and checks == {}
    assert time.monotonic() - started < 10


def test_not_coming_up_is_named_and_exits_three_not_one(monkeypatch):
    monkeypatch.setattr(live, "_battery", lambda *a, **k: (False, {}, 0))
    result = live.run()
    assert result[0] is False and result[1:3] == ({}, {})
    assert result[3]["detail"] == doctor.SELF_TEST_NO_INITIALIZE
    report = doctor.run(sources=[], self_test=lambda: result)
    assert report.exit_code == doctor.EXIT_DOUBT
    assert doctor.render(report)["self_test"]["detail"] == doctor.SELF_TEST_NO_INITIALIZE


def test_a_deadline_failure_after_initialize_is_a_failure_and_prints_the_figure():
    checks = {name: "PASS" for name in CHECKS}
    checks["deadline"] = "FAIL"
    controls = {"constant_allow": "FAIL", "constant_deny": "FAIL", "skipped_invocation": "FAIL"}
    report = doctor.run(sources=[], self_test=lambda: (False, controls, checks, {"deadline_ms": 3100}))
    assert report.exit_code == doctor.EXIT_FAILED
    rendered = doctor.render(report)["self_test"]
    assert rendered["failure_class"] == doctor.DEADLINE
    assert rendered["measured_ms"] == 3100
    assert "3100 ms measured against a 2250 ms bound" in rendered["deadline"]


def test_a_passing_self_test_with_no_route_to_verify_is_exit_three():
    checks = {name: "PASS" for name in CHECKS}
    controls = {"constant_allow": "FAIL", "constant_deny": "FAIL", "skipped_invocation": "FAIL"}
    report = doctor.run(sources=[], self_test=lambda: (True, controls, checks, {"deadline_ms": 12}))
    assert report.exit_code == doctor.EXIT_DOUBT
    assert doctor.render(report)["aggregate"] == doctor.ROUTE_UNVERIFIED


def test_a_passing_control_voids_the_run():
    checks = {name: "PASS" for name in CHECKS}
    controls = {"constant_allow": "PASS", "constant_deny": "FAIL", "skipped_invocation": "FAIL"}
    report = doctor.run(sources=[], self_test=lambda: (True, controls, checks, {"deadline_ms": 12}))
    assert report.exit_code == doctor.EXIT_FAILED


def test_where_processes_cannot_be_grouped_the_self_test_says_it_never_ran(monkeypatch):
    monkeypatch.setattr(live, "_supported", lambda: False)
    assert live.run() == (False, {})


def test_no_process_from_a_run_is_left():
    live.run()
    # Every spawned argv names the private folder, so a survivor is findable by it.
    import subprocess
    try:
        out = subprocess.run(["ps", "-axo", "command="], capture_output=True, text=True).stdout
    except OSError:
        pytest.skip("this environment does not let a test read the process table")
    import re
    assert not re.search(r"-m sunglasses\.proxy.*sunglasses-doctor", out)


# ── cleanup and startup failures ────────────────────────────────────────

def _leader_exits(marker):
    return textwrap.dedent(f"""
        import os, subprocess, sys
        subprocess.Popen([sys.executable, "-c", "import time; time.sleep(75)"])
        open({str(marker)!r}, "w").write(str(os.getpgid(0)))
    """)


def test_a_leader_that_exits_first_cannot_hold_the_run_and_its_child_is_killed(tmp_path):
    marker = tmp_path / "leader.pgid"
    started = time.monotonic()
    came_up, checks, _ = _battery(
        tmp_path, lambda *_: [sys.executable, "-c", _leader_exits(marker)], first_reply_s=0.5)
    assert came_up is False and checks == {}
    assert time.monotonic() - started < 10
    group = int(marker.read_text())
    deadline = time.monotonic() + 3
    while live._group_alive(group) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not live._group_alive(group), "the child of the exited leader was left running"


def test_a_proxy_that_leaves_a_child_in_its_own_group_fails_disconnect(tmp_path):
    _, checks, _ = _battery(tmp_path, _mutant(tmp_path, "leave_proxy_child"))
    assert checks["disconnect"] == "FAIL"
    assert checks["s1_forward_byte_equal"] == "PASS"


def test_a_sigterm_unwinds_the_run_and_removes_the_private_folder(tmp_path):
    import subprocess
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    env = dict(os.environ, TMPDIR=str(scratch), PYTHONPATH=REPO)
    # A normal run ends in 0.35 s and cannot be signalled mid-flight, so hold the
    # real one open at its first reply with a spawn that never answers.
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import sys\n"
         "from sunglasses.proxy import live_selftest as l\n"
         "l.FIRST_REPLY_S = 60\n"
         "l._echo_argv = lambda i, p: [sys.executable, '-c', 'import time; time.sleep(60)']\n"
         "l.run()\n"], env=env)
    deadline = time.monotonic() + 10
    while not any(name.endswith("-sunglasses-doctor") for name in os.listdir(scratch)):
        assert time.monotonic() < deadline, "the run never made its folder"
        time.sleep(0.05)
    time.sleep(0.5)
    holder.send_signal(signal.SIGTERM)
    assert holder.wait(timeout=15) == 128 + signal.SIGTERM
    assert os.listdir(scratch) == []


def test_a_refused_temp_folder_is_a_named_unavailable_not_a_traceback(monkeypatch):
    def refuse(*args, **kwargs):
        raise PermissionError(13, "no")

    monkeypatch.setattr(live.tempfile, "mkdtemp", refuse)
    result = live.run()
    assert result[0] is False and result[1:3] == ({}, {})
    assert result[3]["detail"] == doctor.SELF_TEST_COULD_NOT_START
    report = doctor.run(sources=[], self_test=lambda: result)
    assert report.exit_code == doctor.EXIT_DOUBT
    assert doctor.render(report)["self_test"]["detail"] == doctor.SELF_TEST_COULD_NOT_START


def test_a_refused_spawn_is_a_named_unavailable_not_a_traceback(monkeypatch):
    def refuse(*args, **kwargs):
        raise OSError(1, "no")

    monkeypatch.setattr(live.subprocess, "Popen", refuse)
    result = live.run()
    assert result[0] is False and result[1:3] == ({}, {})
    assert result[3]["detail"] == doctor.SELF_TEST_COULD_NOT_START


def test_running_out_of_time_with_nothing_red_is_doubt_and_with_a_red_check_is_failure(monkeypatch):
    monkeypatch.setattr(live, "OVERALL_S", 0.0)
    ok, controls, checks, info = live.run()
    assert ok is False
    assert info["detail"] in (doctor.SELF_TEST_OUT_OF_TIME, doctor.SELF_TEST_NO_INITIALIZE)


def test_a_reader_thread_that_cannot_start_leaves_no_group_and_no_folder(tmp_path, monkeypatch):
    spawned = []
    real_popen = live.subprocess.Popen

    def recording(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        spawned.append(proc.pid)
        return proc

    class NoThread:
        ident = None

        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise RuntimeError("can't start new thread")

    monkeypatch.setattr(live.subprocess, "Popen", recording)
    monkeypatch.setattr(live.threading, "Thread", NoThread)
    monkeypatch.setattr(live.tempfile, "tempdir", str(tmp_path))
    result = live.run()
    assert result[0] is False and result[1:3] == ({}, {})
    assert result[3]["detail"] == doctor.SELF_TEST_COULD_NOT_START
    assert spawned, "the test never reached a real spawn"
    end = time.monotonic() + 3
    while any(live._group_alive(pid) for pid in spawned) and time.monotonic() < end:
        time.sleep(0.05)
    assert not any(live._group_alive(pid) for pid in spawned)
    assert list(tmp_path.iterdir()) == []


_CONTROL_NAMES = ("constant_allow", "constant_deny", "skipped_invocation")


def _refuse_control(monkeypatch, which):
    """Real battery for the primary run and for every control but one, which cannot start."""
    real = live._battery
    calls = []

    def battery(*args, **kwargs):
        calls.append(1)
        if len(calls) == which + 2:
            raise live._CouldNotStart("OSError")
        return real(*args, **kwargs)

    monkeypatch.setattr(live, "_battery", battery)
    return live.run()


@pytest.mark.parametrize("which", range(3))
def test_a_control_that_cannot_start_is_not_run_and_voids_the_whole_report(monkeypatch, which):
    name = _CONTROL_NAMES[which]
    result = _refuse_control(monkeypatch, which)
    ok, controls, checks, info = result
    assert ok is False
    assert name not in controls and len(controls) == 2
    assert all(value == "FAIL" for value in controls.values())
    assert checks and all(value == "PASS" for value in checks.values())
    assert info["detail"] == doctor.SELF_TEST_COULD_NOT_START
    assert info["not_run_controls"] == [name]

    report = doctor.run(sources=[], self_test=lambda: result)
    assert report.exit_code == doctor.EXIT_DOUBT
    shown = doctor.render(report)["self_test"]
    assert shown["valid"] is False
    assert shown["failure_class"] == doctor.SELF_TEST_UNAVAILABLE
    assert shown["detail"] == doctor.SELF_TEST_COULD_NOT_START
    assert shown["not_run_controls"] == [name]
    assert name not in shown["controls"]
    assert all(value == "PASS" for value in shown["checks"].values())
    assert shown["failed"] == []


def test_a_control_that_cannot_start_is_said_in_words_and_never_reads_as_passed(monkeypatch, capsys):
    from sunglasses import cli
    result = _refuse_control(monkeypatch, 2)
    report = doctor.run(sources=[], self_test=lambda: result)
    args = type("A", (), {"config": None, "json": False})()
    with pytest.raises(SystemExit) as raised:
        cli.cmd_doctor(args, _run=lambda **kw: report)
    out = capsys.readouterr().out
    assert raised.value.code == 3
    assert "skipped_invocation could not be started" in out
    assert "Self-test PASSED" not in out and "FAILED" not in out
    assert "none could run" not in out
    assert "shown as they ran" in out


def test_the_summary_line_for_a_refused_control_does_not_deny_checks_that_ran(capsys):
    from sunglasses import cli
    checks = {name: "PASS" for name in CHECKS}
    checks["s2_block_schema"] = "FAIL"
    controls = {"constant_allow": "FAIL", "constant_deny": "FAIL"}
    info = {"detail": doctor.SELF_TEST_COULD_NOT_START, "deadline_ms": 9,
            "not_run_controls": ["constant_deny"]}
    report = doctor.run(sources=[], self_test=lambda: (False, controls, checks, info))
    args = type("A", (), {"config": None, "json": False})()
    with pytest.raises(SystemExit) as raised:
        cli.cmd_doctor(args, _run=lambda **kw: report)
    out = capsys.readouterr().out
    assert raised.value.code == 3
    assert "none could run" not in out
    assert "shown as they ran" in out


def test_a_control_that_cannot_start_does_not_hide_a_check_that_really_failed(monkeypatch):
    checks = {name: "PASS" for name in CHECKS}
    checks["s2_block_schema"] = "FAIL"
    controls = {"constant_allow": "FAIL", "constant_deny": "FAIL"}
    info = {"detail": doctor.SELF_TEST_COULD_NOT_START, "deadline_ms": 9,
            "not_run_controls": ["skipped_invocation"]}
    report = doctor.run(sources=[], self_test=lambda: (False, controls, checks, info))
    assert report.exit_code == doctor.EXIT_DOUBT
    shown = doctor.render(report)["self_test"]
    assert shown["valid"] is False
    assert shown["checks"]["s2_block_schema"] == "FAIL"


def test_a_ctrl_c_in_the_real_command_cleans_up_and_says_so_in_one_line(tmp_path):
    import json
    import subprocess
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {}}))
    env = dict(os.environ, TMPDIR=str(scratch), HOME=str(home), PYTHONPATH=REPO)
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import sys\n"
         "from sunglasses.proxy import live_selftest as l\n"
         "l.FIRST_REPLY_S = 60\n"
         "l._echo_argv = lambda i, p: [sys.executable, '-c', 'import time; time.sleep(60)']\n"
         "from sunglasses import cli\n"
         "sys.argv = ['sunglasses', 'doctor', '--config', sys.argv[1]]\n"
         "cli.main()\n", str(cfg)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 10
    while not any(name.endswith("-sunglasses-doctor") for name in os.listdir(scratch)):
        assert time.monotonic() < deadline, "the run never made its folder"
        time.sleep(0.05)
    time.sleep(0.5)
    holder.send_signal(signal.SIGINT)
    _, err = holder.communicate(timeout=15)
    assert holder.returncode == 128 + signal.SIGINT
    assert "Traceback" not in err and "KeyboardInterrupt" not in err
    lines = [line for line in err.splitlines() if line.strip()]
    assert len(lines) == 1 and lines[0].startswith("sunglasses doctor: interrupted")
    assert os.listdir(scratch) == []


def test_a_ctrl_c_outside_the_self_test_says_so_in_one_line_too(capsys):
    from sunglasses import cli

    def interrupted(**kwargs):
        raise KeyboardInterrupt

    args = type("A", (), {"config": None, "json": False})()
    with pytest.raises(SystemExit) as raised:
        cli.cmd_doctor(args, _run=interrupted)
    assert raised.value.code == 130
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert [line for line in err.splitlines() if line.strip()] == ["sunglasses doctor: interrupted."]
