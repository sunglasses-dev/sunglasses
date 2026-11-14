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
