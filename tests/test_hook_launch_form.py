"""The `doctor` hook launch-form row (C1329): reads a settings file, says which form the hook line
holds, never writes, never changes the exit code."""
import json
import os
import shlex
import stat
import subprocess
import sys

import pytest

from sunglasses import _launch, firewall

NEW = firewall.build_hook_entry()["hooks"][0]["command"]
START_UP = " ".join(shlex.quote(w) for w in [sys.executable, "-c", _launch.bootstrap(firewall.HOOK_MARKER)])
OLD = f"{shlex.quote(sys.executable)} -m {firewall.HOOK_MARKER}"


def _settings(tmp_path, command, name="settings.json"):
    p = tmp_path / ".claude" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": ".*", "hooks": [{"type": "command", "command": command}]}]}}))
    return p


def test_a_hook_written_now_is_ok(tmp_path):
    rows = firewall.hook_launch_form([_settings(tmp_path, NEW)])
    assert [r["state"] for r in rows] == ["OK"] and rows[0]["fix"] is None


def test_the_start_up_line_form_is_ok_too(tmp_path):
    assert [r["state"] for r in firewall.hook_launch_form([_settings(tmp_path, START_UP)])] == ["OK"]


def test_the_old_m_form_is_old_and_names_init(tmp_path):
    rows = firewall.hook_launch_form([_settings(tmp_path, OLD)])
    assert rows[0]["state"] == "OLD" and rows[0]["fix"] == "sunglasses init" and rows[0]["by_hand"] is None


@pytest.mark.parametrize("command", [
    f"{sys.executable} -I -m {firewall.HOOK_MARKER}",           # not one of our shapes
    f"{sys.executable} -m {firewall.HOOK_MARKER} --extra",
    f"env X=1 {sys.executable} -m {firewall.HOOK_MARKER}",
    f"{sys.executable} -P -m {firewall.HOOK_MARKER}; echo hi",
    f"'{sys.executable} -m {firewall.HOOK_MARKER}",             # unbalanced quote
])
def test_a_line_we_cannot_judge_is_unverified_with_the_line_to_use(tmp_path, command):
    rows = firewall.hook_launch_form([_settings(tmp_path, command)])
    assert rows[0]["state"] == "UNVERIFIED"
    assert firewall.HOOK_MARKER in rows[0]["by_hand"]


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="needs a non-root POSIX user")
def test_an_old_line_in_an_unwritable_file_is_unverified_not_old(tmp_path):
    p = _settings(tmp_path, OLD)
    p.chmod(stat.S_IRUSR)
    try:
        rows = firewall.hook_launch_form([p])
    finally:
        p.chmod(stat.S_IRUSR | stat.S_IWUSR)
    assert rows[0]["state"] == "UNVERIFIED" and rows[0]["fix"] is None
    assert rows[0]["by_hand"].split()[0] == shlex.quote(sys.executable)


def test_other_hooks_and_missing_files_are_not_rows(tmp_path):
    other = _settings(tmp_path, "/usr/bin/true", name="other.json")
    assert firewall.hook_launch_form([other, tmp_path / "absent.json"]) == []


def test_the_check_never_writes(tmp_path):
    p = _settings(tmp_path, OLD)
    before = (p.read_bytes(), p.stat().st_mtime_ns)
    firewall.hook_launch_form([p])
    assert (p.read_bytes(), p.stat().st_mtime_ns) == before
    assert not list(tmp_path.rglob("*.bak*"))


def test_init_rewrites_an_old_line_into_an_ok_one(tmp_path):
    p = _settings(tmp_path, OLD)
    firewall.install_hook(p)
    assert [r["state"] for r in firewall.hook_launch_form([p])] == ["OK"]


def test_doctor_reports_the_row_and_keeps_its_exit_code(tmp_path):
    """Through the real command: JSON carries the row, text names the fix, and the exit code is
    the same with an old line as with none."""
    home = tmp_path / "home"
    project = tmp_path / "project"
    project.mkdir()
    _settings(home, OLD)
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
    root = os.path.dirname(os.path.dirname(os.path.abspath(firewall.__file__)))
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    run = lambda *a, e=env: subprocess.run([sys.executable, "-P", "-m", "sunglasses", "doctor", *a],
                                           cwd=project, env=e, capture_output=True, text=True, timeout=120)
    js = run("--json")
    doc = json.loads(js.stdout)
    assert [r["state"] for r in doc["hook_launch"]] == ["OLD"]
    text = run().stdout
    assert "Hook launch form" in text and "sunglasses init" in text

    clean = tmp_path / "clean"
    clean.mkdir()
    env2 = {**env, "HOME": str(clean), "USERPROFILE": str(clean)}
    js2 = run("--json", e=env2)
    assert "hook_launch" not in json.loads(js2.stdout)
    assert js.returncode == js2.returncode


def test_init_over_an_old_hook_line_leaves_exactly_one_entry_of_ours_in_the_current_form(tmp_path):
    """C1329, through the real `sunglasses init` in a sandboxed project and HOME: an OLD `-m` line
    is replaced, not added to. One entry of ours remains, in the current form, and the entry
    that belongs to someone else is untouched."""
    home, project = tmp_path / "home", tmp_path / "proj"
    project.mkdir()
    home.mkdir()
    settings = project / ".claude" / "settings.json"
    settings.parent.mkdir()
    other = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/bin/true"}]}
    ours_old = {"matcher": ".*", "hooks": [{"type": "command", "command": OLD, "timeout": 10}]}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [other, ours_old]}}))

    env = {**os.environ, "HOME": str(home), "SUNGLASSES_HOME": str(home / ".sunglasses"),
           "PYTHONPATH": os.path.dirname(os.path.dirname(os.path.abspath(firewall.__file__)))}
    done = subprocess.run([sys.executable, "-P", "-m", "sunglasses", "init"], cwd=str(project),
                          env=env, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr

    pre = json.loads(settings.read_text())["hooks"]["PreToolUse"]
    ours = [h for e in pre for h in e["hooks"] if firewall.HOOK_MARKER in h["command"]]
    assert len(ours) == 1
    assert ours[0]["command"] == NEW
    assert other in pre
    assert [r["state"] for r in firewall.hook_launch_form([settings])] == ["OK"]


# ---- the whole line is judged, not word by word (C1329 r2) ------------------------------------

PY = "/usr/bin/python3"
QUOTED = "'/Users/x/My Env/bin/python3'"
LOCAL_ROWS = os.path.expanduser("~/.claude/state/warroom/C1365_B2_NEAR_MISS_2026-11-14.json")
CHOICE = {"N1", "N2"}          # either answer accepted when the table was written


@pytest.mark.parametrize("command", [
    f"{PY}>/tmp/mark;sh -P -m {firewall.HOOK_MARKER}",          # redirect and separator glued to the first word
    f"true&&{PY} -P -m {firewall.HOOK_MARKER}",
    f"false||{PY} -P -m {firewall.HOOK_MARKER}",
    f"{PY}|cat -P -m {firewall.HOOK_MARKER}",
    f"{PY}&sh -P -m {firewall.HOOK_MARKER}",
    f"$(id){PY} -P -m {firewall.HOOK_MARKER}",
    f"{PY}<in.txt -P -m {firewall.HOOK_MARKER}",
    f"$HOME/bin/python3 -P -m {firewall.HOOK_MARKER}",
    f"~/venv/bin/python3 -P -m {firewall.HOOK_MARKER}",
    f"{PY}>/tmp/mark;sh -m {firewall.HOOK_MARKER}",              # the old form must not read as OLD either
    f"{PY}\ntouch /tmp/mark\n-P -m {firewall.HOOK_MARKER}",
    f"{PY} -P -m {firewall.HOOK_MARKER}\ntouch /tmp/mark",
])
def test_shell_syntax_glued_into_the_line_is_unverified_not_ok_or_old(command):
    assert firewall._hook_form_of(command)[0] == "UNVERIFIED"


@pytest.mark.parametrize("command,state", [
    (f"{PY} -P -m {firewall.HOOK_MARKER}", "OK"),
    (f"{QUOTED} -P -m {firewall.HOOK_MARKER}", "OK"),
    (f'"{PY}" -P -m {firewall.HOOK_MARKER}', "OK"),
    (f"{QUOTED} -m {firewall.HOOK_MARKER}", "OLD"),
    (f"{PY} -m {firewall.HOOK_MARKER}", "OLD"),
])
def test_the_forms_the_writer_makes_and_quoted_interpreter_paths_stay_as_they_were(command, state):
    assert firewall._hook_form_of(command)[0] == state


def test_the_start_up_line_with_a_quoted_interpreter_stays_ok():
    line = " ".join(shlex.quote(w) for w in ["/Users/x/My Env/bin/python3", "-c", _launch.bootstrap(firewall.HOOK_MARKER)])
    assert firewall._hook_form_of(line)[0] == "OK"


def test_a_compound_line_in_a_settings_file_gets_the_line_to_use_and_nothing_is_written(tmp_path):
    path = _settings(tmp_path, f"{PY}>/tmp/mark;sh -P -m {firewall.HOOK_MARKER}")
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    rows = firewall.hook_launch_form([path])
    assert rows[0]["state"] == "UNVERIFIED" and rows[0]["by_hand"] and firewall.HOOK_MARKER in rows[0]["by_hand"]
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


@pytest.mark.skipif(not os.path.exists(LOCAL_ROWS), reason="the near-miss table lives on one machine")
def test_every_row_of_the_local_near_miss_table_gets_its_expected_state():
    with open(LOCAL_ROWS, encoding="utf-8") as handle:
        rows = json.load(handle)
    assert len(rows) >= 34
    wrong = [(r["id"], r["expected"], firewall._hook_form_of(r["line"])[0])
             for r in rows if r["id"] not in CHOICE and firewall._hook_form_of(r["line"])[0] != r["expected"]]
    assert not wrong, wrong
