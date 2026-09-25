"""
test_firewall_stat_first.py — ONLY "NOTHING IS THERE" IS ABSENT (T9 ruling 59, Q4).

The three loaders the hook reads on every call (policy.yaml, pins.json,
pin_state.json) each asked `Path.exists()` first and treated False as "never
installed". `exists()` answers False for more than a missing file, and what it
does with the rest depends on the interpreter:

  - A home the hook cannot search (EACCES) raised PermissionError out of the
    loader on 3.11 to 3.13, which no caller catches, and returned False on
    3.14: `{}`, the answer of a machine that never installed a policy.
  - A symlink loop (ELOOP) or a home that is a file (ENOTDIR) returned False on
    every version.

Either way the control was off and said nothing, or the hook crashed, and a
crashed hook lets the call through. The loaders now stat first: ENOENT is
absent, and every other OSError is the lane's named "unreadable" failure.
"""
import errno
import json
import os

import pytest

from sunglasses import firewall
from sunglasses.firewall import PolicyDown, PolicyError, run_hook, starter_policy_text

CLEAN = json.dumps({
    "hook_event_name": "PreToolUse", "tool_name": "Bash",
    "tool_input": {"command": "echo hello"}, "session_id": "stat-first",
})

LOADERS = {
    "policy": ("policy.yaml", firewall.load_policy, starter_policy_text(enabled=True)),
    "pins": ("pins.json", firewall.load_pins, '{"tools": {}}'),
    "pin_state": ("pin_state.json", firewall.load_pin_state, '{"drifted": {}}'),
}
SHAPES = {"eacces": errno.EACCES, "eloop": errno.ELOOP, "enotdir": errno.ENOTDIR}


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "sunglasses-home"
    h.mkdir()
    yield h
    os.chmod(h, 0o700)


def _place(home, shape, name, content):
    """Put the loader's file behind `shape` and return its path. The stimulus is
    proven: stat on that path raises exactly the errno the shape names."""
    if shape == "eacces":
        if os.geteuid() == 0:
            pytest.skip("root searches a mode 000 directory")
        path = home / name
        path.write_text(content)
        os.chmod(home, 0o000)
    elif shape == "eloop":
        path = home / name
        path.symlink_to(path)
    else:
        blocker = home / "not-a-directory"
        blocker.write_text("a file\n")
        path = blocker / name
    with pytest.raises(OSError) as info:
        os.stat(path)
    assert info.value.errno == SHAPES[shape], (shape, info.value)
    return path


def _expect_unreadable(loader_key, call, path):
    if loader_key == "policy":
        with pytest.raises(PolicyDown) as info:
            call(path)
        assert info.value.state == "unreadable", info.value.state
    else:
        # The pin lanes' named failure is PolicyError: it is what run_hook and
        # `pin --check` catch, and a PolicyDown would escape both.
        with pytest.raises(PolicyError) as info:
            call(path)
        assert "unreadable" in str(info.value), str(info.value)
    assert str(path) in str(info.value), str(info.value)


@pytest.mark.parametrize("shape", sorted(SHAPES))
@pytest.mark.parametrize("loader_key", sorted(LOADERS))
def test_a_path_that_cannot_be_stat_is_unreadable_never_absent(home, loader_key, shape):
    name, call, content = LOADERS[loader_key]
    (home / firewall.INSTALL_MARKER).write_text("installed here\n")
    path = _place(home, shape, name, content)
    _expect_unreadable(loader_key, call, path)


@pytest.mark.parametrize("shape", sorted(SHAPES))
@pytest.mark.parametrize("loader_key", sorted(LOADERS))
def test_no_install_marker_does_not_turn_unreadable_into_absent(home, loader_key, shape):
    """The marker only decides what a MISSING policy means. It must not decide
    what an unreadable one means: with no marker the old code's `{}` was the
    never-installed answer, which is the off switch itself."""
    name, call, content = LOADERS[loader_key]
    path = _place(home, shape, name, content)
    _expect_unreadable(loader_key, call, path)


def test_an_install_marker_that_cannot_be_stat_is_not_never_installed(home):
    marker = home / firewall.INSTALL_MARKER
    marker.symlink_to(marker)
    with pytest.raises(PolicyDown) as info:
        firewall.load_policy(home / "policy.yaml")
    assert info.value.state == "unreadable", info.value.state
    assert str(marker) in str(info.value), str(info.value)


def test_a_policy_in_a_symlink_loop_asks_and_names_the_policy(home):
    """End to end, with no install marker: the old hook answered `{}` here."""
    path = home / "policy.yaml"
    path.symlink_to(path)
    out = run_hook(CLEAN, home=home).get("hookSpecificOutput", {})
    assert out.get("permissionDecision") == "ask", out
    reason = out.get("permissionDecisionReason", "")
    assert "cannot be read" in reason and "policy" in reason.lower(), reason


# ── controls: absent is still absent ─────────────────────────────────────────

@pytest.mark.parametrize("loader_key,absent", [
    ("policy", {}), ("pins", {"tools": {}}), ("pin_state", None)])
def test_the_control_a_file_that_is_not_there_is_still_absent(home, loader_key, absent):
    name, call, _ = LOADERS[loader_key]
    assert call(home / name) == absent


def test_the_control_a_missing_policy_after_install_is_still_missing(home):
    (home / firewall.INSTALL_MARKER).write_text("installed here\n")
    with pytest.raises(PolicyDown) as info:
        firewall.load_policy(home / "policy.yaml")
    assert info.value.state == "missing", info.value.state


def test_the_control_a_home_that_does_not_exist_is_never_installed(tmp_path):
    assert firewall.load_policy(tmp_path / "no-home" / "policy.yaml") == {}


@pytest.mark.parametrize("loader_key", sorted(LOADERS))
def test_the_control_a_readable_file_still_loads(home, loader_key):
    name, call, content = LOADERS[loader_key]
    (home / name).write_text(content)
    assert call(home / name) is not None
