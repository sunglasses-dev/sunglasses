"""`sunglasses init` writes `"onFailure": "block"` into the hook it installs.

Claude Code lets a tool call go ahead when its hook fails (a timeout, a hook that
cannot start, output it cannot read) unless the hook entry says otherwise. For a
firewall that is the wrong default: the failure is silent and the firewall looks
on while it is off. The entry therefore asks the host to block on failure, and
`init --fail-open` leaves the key out for anyone who prefers the old behaviour.

Blocking on failure also makes a broken hook loud: if the command cannot run, every
tool call is refused. So the install self-test has to catch that before the entry
is written, and has to judge the hook by the same time limit the host applies.

These tests only touch temp files. They do not run Claude Code, and they say
nothing about which Claude Code versions read the key.
"""

import json
import os
import subprocess
import sys

import pytest

from sunglasses import firewall
from sunglasses.firewall import (
    HOOK_MARKER,
    _HOOK_TIMEOUT,
    build_hook_entry,
    install_hook,
    self_test_hook,
    uninstall_hook,
)


def _hook_of(entry):
    (hook,) = entry["hooks"]
    return hook


def _installed(path):
    pre = json.loads(path.read_text())["hooks"]["PreToolUse"]
    return [h for entry in pre for h in entry["hooks"] if HOOK_MARKER in h["command"]]


# ── the entry ───────────────────────────────────────────────────────────────

def test_the_entry_asks_the_host_to_block_when_the_hook_fails():
    assert _hook_of(build_hook_entry())["onFailure"] == "block"


def test_the_fail_open_entry_leaves_the_key_out():
    # Not "continue": an absent key is the host's own default and is what every
    # earlier install wrote, so opting out changes nothing for older hosts.
    assert "onFailure" not in _hook_of(build_hook_entry(fail_open=True))


def test_the_timeout_is_unchanged_and_the_rest_of_the_entry_is_the_same():
    blocking, open_ = build_hook_entry(), build_hook_entry(fail_open=True)
    assert _hook_of(blocking)["timeout"] == _HOOK_TIMEOUT == 10
    assert {k: v for k, v in _hook_of(blocking).items() if k != "onFailure"} == _hook_of(open_)
    assert blocking["matcher"] == open_["matcher"] == ".*"
    assert _hook_of(open_)["type"] == "command"


# ── the install ─────────────────────────────────────────────────────────────

def test_install_writes_the_blocking_entry_by_default(tmp_path):
    path = tmp_path / "settings.json"
    install_hook(path)
    (hook,) = _installed(path)
    assert hook["onFailure"] == "block"
    assert hook["timeout"] == 10


def test_install_with_fail_open_writes_no_key(tmp_path):
    path = tmp_path / "settings.json"
    install_hook(path, fail_open=True)
    (hook,) = _installed(path)
    assert "onFailure" not in hook


def test_a_rerun_switches_the_mode_and_never_adds_a_second_entry(tmp_path):
    path = tmp_path / "settings.json"
    install_hook(path)
    install_hook(path, fail_open=True)
    (hook,) = _installed(path)
    assert "onFailure" not in hook
    install_hook(path)
    (hook,) = _installed(path)
    assert hook["onFailure"] == "block"


def test_install_keeps_another_hook_exactly_as_it_was(tmp_path):
    other = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/x/other.sh", "onFailure": "continue"}]}
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"hooks": {"PreToolUse": [other]}}))
    install_hook(path)
    assert json.loads(path.read_text())["hooks"]["PreToolUse"][0] == other


def test_uninstall_removes_the_blocking_entry(tmp_path):
    path = tmp_path / "settings.json"
    install_hook(path)
    uninstall_hook(path)
    assert HOOK_MARKER not in path.read_text()


# ── the self-test is what keeps a broken wire from blocking every tool ──────

def test_an_interpreter_that_does_not_exist_fails_the_self_test(tmp_path):
    ok, detail = self_test_hook(f"{tmp_path / 'no-such-python'} -m {HOOK_MARKER}")
    assert not ok
    assert detail


def test_the_self_test_applies_the_limit_it_is_given(tmp_path):
    slow = tmp_path / "python3"
    slow.write_text("#!/bin/sh\nsleep 5\n")
    slow.chmod(0o755)
    ok, detail = self_test_hook(f"{slow} -m {HOOK_MARKER}", timeout=1)
    assert not ok
    assert "could not run" in detail


def test_the_self_test_default_limit_is_unchanged(tmp_path):
    # A hook that answers after 2 s passes under the default limit.
    slow = tmp_path / "python3"
    slow.write_text("#!/bin/sh\nsleep 2\necho '{}'\n")
    slow.chmod(0o755)
    ok, _ = self_test_hook(f"{slow} -m {HOOK_MARKER}")
    assert ok


# ── the command ─────────────────────────────────────────────────────────────

class _Args:
    def __init__(self, **kw):
        self.scope_global = False
        self.uninstall = False
        self.policy = False
        self.no_policy = True
        self.fail_open = False
        self.__dict__.update(kw)


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SUNGLASSES_HOME", str(tmp_path / "home" / ".sunglasses"))
    return tmp_path


def test_init_judges_a_blocking_hook_by_the_host_time_limit(project, monkeypatch, capsys):
    from sunglasses import cli
    seen = {}

    def fake(command, **kw):
        seen.update(kw)
        return True, "defer"

    monkeypatch.setattr(firewall, "self_test_hook", fake)
    assert cli.cmd_init(_Args()) == 0
    assert seen == {"timeout": _HOOK_TIMEOUT}
    (hook,) = _installed(project / ".claude" / "settings.json")
    assert hook["onFailure"] == "block"


def test_init_with_fail_open_keeps_the_old_self_test_limit(project, monkeypatch, capsys):
    from sunglasses import cli
    seen = {}

    def fake(command, **kw):
        seen.update(kw)
        return True, "defer"

    monkeypatch.setattr(firewall, "self_test_hook", fake)
    assert cli.cmd_init(_Args(fail_open=True)) == 0
    assert seen == {}
    (hook,) = _installed(project / ".claude" / "settings.json")
    assert "onFailure" not in hook


@pytest.mark.parametrize("fail_open", [False, True])
def test_init_writes_nothing_when_the_self_test_fails(project, monkeypatch, capsys, fail_open):
    from sunglasses import cli
    monkeypatch.setattr(firewall, "self_test_hook", lambda command, **kw: (False, "exit code 127"))
    assert cli.cmd_init(_Args(fail_open=fail_open)) == 1
    assert not (project / ".claude" / "settings.json").exists()


def test_init_says_what_it_wrote_and_how_to_opt_out(project, monkeypatch, capsys):
    from sunglasses import cli
    monkeypatch.setattr(firewall, "self_test_hook", lambda command, **kw: (True, "defer"))
    cli.cmd_init(_Args())
    out = capsys.readouterr().out
    assert "onFailure" in out and "--fail-open" in out
    # A refused tool call cannot be repaired from inside the session, so the way
    # out is said at install time.
    assert "--uninstall" in out and "settings.json" in out


def test_init_with_fail_open_does_not_claim_a_failure_policy(project, monkeypatch, capsys):
    from sunglasses import cli
    monkeypatch.setattr(firewall, "self_test_hook", lambda command, **kw: (True, "defer"))
    cli.cmd_init(_Args(fail_open=True))
    out = capsys.readouterr().out
    assert "onFailure" not in out
    assert "fail-open" in out.lower() or "fails open" in out.lower()


def test_the_flag_is_on_the_command_line():
    proc = subprocess.run([sys.executable, "-m", "sunglasses", "init", "--help"], capture_output=True,
                          text=True, env={**os.environ, "PYTHONPATH": str(__import__("pathlib").Path(__file__).parent.parent)})
    assert "--fail-open" in proc.stdout
