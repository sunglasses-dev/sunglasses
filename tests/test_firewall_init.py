"""
test_firewall_init.py — `sunglasses init` / `--uninstall` (P4).

`init` edits a settings file the user already depends on. Getting this wrong
does not produce a false positive — it produces a broken Claude Code config, or
a firewall that is silently not running. So the bar here is different from the
other phases: **never lose data that was already in the file, and never leave a
hook wired to an interpreter that cannot import us.**

The PATH hazard (flagged by T9 at 23:06, and it is the sharp one): writing a
literal `python3 -m sunglasses.firewall` resolves through PATH at hook time.
Under pipx / venv / conda that can be a *different* interpreter with no
`sunglasses` installed — the hook then fails, the failure is invisible, and the
firewall is off while looking on. So `init` writes the absolute interpreter it
was run with, and self-tests the exact command it wrote.

Every test here operates on temp fixtures. AZ's real ~/.claude/settings.json is
never opened.
"""

import json
import os
import subprocess
import sys

import pytest

from sunglasses.firewall import (
    HOOK_MARKER,
    build_hook_entry,
    install_hook,
    self_test_hook,
    uninstall_hook,
)


EXISTING = {
    "model": "opus",
    "hooks": {
        "PreToolUse": [
            {"matcher": "Bash", "hooks": [
                {"type": "command", "command": "/Users/az/.claude/hooks/skill-router-block.sh"}]}
        ],
        "SessionStart": [
            {"matcher": "startup", "hooks": [
                {"type": "command", "command": "~/.claude/hooks/boot-inject.sh"}]}
        ],
    },
    "permissions": {"allow": ["Bash(git status)"]},
}


@pytest.fixture
def settings(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(EXISTING, indent=2))
    return path


def _read(path):
    return json.loads(path.read_text())


# ── the hook entry itself ───────────────────────────────────────────────────

def test_hook_entry_uses_an_absolute_interpreter():
    """The whole PATH hazard in one assertion."""
    entry = build_hook_entry()
    command = entry["hooks"][0]["command"]
    assert command.startswith("/"), f"relative interpreter in hook command: {command}"
    assert sys.executable in command


def test_hook_entry_targets_the_fast_module_not_the_cli():
    """cli.py costs ~109ms of module-scope imports; the module path costs ~27ms."""
    command = build_hook_entry()["hooks"][0]["command"]
    assert "sunglasses.firewall" in command
    assert "firewall-hook" not in command


def test_hook_entry_matches_every_tool():
    """policy blocked_paths must cover Read/Edit too, not just egress tools."""
    assert build_hook_entry()["matcher"] == ".*"


def test_hook_entry_has_a_timeout():
    """Default is 600s. A hook that can hang for ten minutes on every tool call
    is a worse outage than the attacks it prevents."""
    timeout = build_hook_entry()["hooks"][0].get("timeout")
    assert timeout and timeout <= 30


def test_hook_entry_is_identifiable():
    assert HOOK_MARKER in json.dumps(build_hook_entry())


# ── installing ──────────────────────────────────────────────────────────────

def test_install_preserves_every_existing_key(settings):
    install_hook(settings)
    data = _read(settings)
    assert data["model"] == "opus"
    assert data["permissions"] == {"allow": ["Bash(git status)"]}
    assert data["hooks"]["SessionStart"] == EXISTING["hooks"]["SessionStart"]


def test_install_merges_and_does_not_clobber_other_pretooluse_hooks(settings):
    install_hook(settings)
    entries = _read(settings)["hooks"]["PreToolUse"]
    commands = json.dumps(entries)
    assert "skill-router-block.sh" in commands, "clobbered the user's existing hook"
    assert HOOK_MARKER in commands


def test_install_into_a_file_with_no_hooks_key(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"model": "opus"}))
    install_hook(path)
    assert _read(path)["model"] == "opus"
    assert HOOK_MARKER in json.dumps(_read(path)["hooks"]["PreToolUse"])


def test_install_creates_the_file_when_absent(tmp_path):
    path = tmp_path / "nested" / "settings.json"
    install_hook(path)
    assert HOOK_MARKER in json.dumps(_read(path))


def test_install_is_idempotent(settings):
    install_hook(settings)
    once = _read(settings)
    install_hook(settings)
    install_hook(settings)
    assert _read(settings) == once
    assert json.dumps(_read(settings)).count(HOOK_MARKER) == 1


def test_reinstall_refreshes_a_stale_interpreter_path(settings):
    """A user moves their venv. Re-running init must FIX the wiring, not add a
    second entry pointing at a python that no longer exists."""
    install_hook(settings)
    data = _read(settings)
    for entry in data["hooks"]["PreToolUse"]:
        for hook in entry.get("hooks", []):
            if HOOK_MARKER in hook.get("command", ""):
                hook["command"] = "/old/dead/venv/bin/python -m sunglasses.firewall"
    settings.write_text(json.dumps(data))

    install_hook(settings)
    commands = json.dumps(_read(settings))
    assert "/old/dead/venv" not in commands
    assert commands.count(HOOK_MARKER) == 1


def test_install_backs_up_the_original_first(settings):
    original = settings.read_text()
    install_hook(settings)
    backups = list(settings.parent.glob("settings.json.sunglasses-backup-*"))
    assert len(backups) == 1
    assert backups[0].read_text() == original


def test_install_refuses_to_touch_a_file_it_cannot_parse(tmp_path):
    """Better to stop than to overwrite a config we did not understand."""
    path = tmp_path / "settings.json"
    path.write_text("{ this is not json")
    with pytest.raises(Exception):
        install_hook(path)
    assert path.read_text() == "{ this is not json"


# ── uninstalling ────────────────────────────────────────────────────────────

def test_uninstall_removes_only_our_entry(settings):
    install_hook(settings)
    uninstall_hook(settings)
    data = _read(settings)
    assert HOOK_MARKER not in json.dumps(data)
    assert "skill-router-block.sh" in json.dumps(data["hooks"]["PreToolUse"])
    assert data["hooks"]["SessionStart"] == EXISTING["hooks"]["SessionStart"]


def test_uninstall_restores_the_file_to_its_original_shape(settings):
    before = _read(settings)
    install_hook(settings)
    uninstall_hook(settings)
    assert _read(settings) == before


def test_uninstall_is_safe_when_not_installed(settings):
    before = _read(settings)
    uninstall_hook(settings)
    assert _read(settings) == before


def test_uninstall_on_a_missing_file_is_a_no_op(tmp_path):
    uninstall_hook(tmp_path / "absent.json")  # must not raise


def test_uninstall_does_not_leave_an_empty_pretooluse_stub(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"model": "opus"}))
    install_hook(path)
    uninstall_hook(path)
    assert _read(path) == {"model": "opus"}, "left config litter behind"


# ── the self-test: catch a broken wire at install time, not at 3am ──────────

def test_self_test_passes_for_the_real_command():
    ok, detail = self_test_hook(build_hook_entry()["hooks"][0]["command"])
    assert ok, detail


def test_self_test_fails_for_an_interpreter_without_sunglasses(tmp_path):
    """The exact pipx/venv failure T9 flagged, reproduced.

    A python that cannot import sunglasses must be caught HERE — otherwise the
    hook fails silently forever and the firewall is off while looking on.
    """
    fake = tmp_path / "python3"
    fake.write_text("#!/bin/sh\nexit 1\n")
    fake.chmod(0o755)
    ok, detail = self_test_hook(f"{fake} -m sunglasses.firewall")
    assert not ok
    assert detail


def test_self_test_fails_when_the_command_returns_garbage(tmp_path):
    fake = tmp_path / "python3"
    fake.write_text("#!/bin/sh\necho 'not json'\n")
    fake.chmod(0o755)
    ok, _ = self_test_hook(f"{fake} -m sunglasses.firewall")
    assert not ok


def test_self_test_sends_a_benign_payload_only(tmp_path):
    """The probe must not itself trip a block, or every install reports failure."""
    capture = tmp_path / "seen.txt"
    fake = tmp_path / "python3"
    fake.write_text(
        "#!/bin/sh\ncat > %s\n"
        "echo '{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\","
        "\"permissionDecision\":\"defer\"}}'\n" % capture)
    fake.chmod(0o755)
    ok, _ = self_test_hook(f"{fake} -m sunglasses.firewall")
    assert ok
    payload = json.loads(capture.read_text())
    assert payload["hook_event_name"] == "PreToolUse"
    assert payload["tool_name"]


# ── CLI ─────────────────────────────────────────────────────────────────────

def _cli(args, home, cwd):
    home.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [sys.executable, "-m", "sunglasses"] + args,
        capture_output=True, text=True, cwd=str(cwd),
        env={**os.environ, "HOME": str(home), "SUNGLASSES_HOME": str(home / ".sunglasses"),
             "PYTHONPATH": str(__import__("pathlib").Path(__file__).parent.parent)},
    )


def test_init_writes_project_settings(tmp_path):
    home, project = tmp_path / "home", tmp_path / "proj"
    project.mkdir()
    proc = _cli(["init"], home, project)
    assert proc.returncode == 0, proc.stderr
    data = _read(project / ".claude" / "settings.json")
    assert HOOK_MARKER in json.dumps(data)


def test_init_global_writes_home_settings_and_not_the_project(tmp_path):
    home, project = tmp_path / "home", tmp_path / "proj"
    project.mkdir()
    assert _cli(["init", "--global"], home, project).returncode == 0
    assert HOOK_MARKER in (home / ".claude" / "settings.json").read_text()
    assert not (project / ".claude" / "settings.json").exists()


def test_init_uninstall_round_trip_via_cli(tmp_path):
    home, project = tmp_path / "home", tmp_path / "proj"
    project.mkdir()
    _cli(["init"], home, project)
    assert _cli(["init", "--uninstall"], home, project).returncode == 0
    assert HOOK_MARKER not in (project / ".claude" / "settings.json").read_text()


def test_init_reports_the_self_test_result_to_the_user(tmp_path):
    home, project = tmp_path / "home", tmp_path / "proj"
    project.mkdir()
    out = _cli(["init"], home, project).stdout.lower()
    assert "self-test" in out or "verified" in out
