"""The run-alone guard's decision: refuse a live holder, reclaim a dead one."""
import os
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
# The BOUNDARY dir too: the session conftest has an autouse fixture that does
# `import grade`, and grade.py lives there. Adding only this directory shadows
# nothing but leaves that import unresolvable when this file is collected alone.
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
# The module lives on main at `tools/run_alone.py`; this suite no longer keeps
# its own copy. → tests/test_run_alone.py covers it there as well.
sys.path.insert(0, str(HERE.parents[2] / "tools"))

import run_alone  # noqa: E402


def test_a_live_pid_is_reported_alive():
    assert run_alone.holder_alive(os.getpid()) is True


def test_a_dead_pid_is_reported_dead():
    """THE ONE THAT MATTERS. A guard that calls a dead holder alive locks the
    suite out forever after any crash — the guard becomes the outage."""
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    assert run_alone.holder_alive(dead.pid) is False


def test_a_lock_naming_a_dead_pid_is_not_a_holder(tmp_path):
    lock = tmp_path / "l"
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    lock.write_text(str(dead.pid))
    assert run_alone.current_holder(lock) is None


def test_a_lock_naming_a_live_pid_IS_a_holder(tmp_path):
    """THE CONTROL. Without it, a guard that always returns None passes every
    row above and refuses nothing."""
    lock = tmp_path / "l"
    live = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        lock.write_text(str(live.pid))
        assert run_alone.current_holder(lock) == live.pid
    finally:
        live.kill(); live.wait()


def test_our_own_pid_is_not_treated_as_a_competitor(tmp_path):
    """Re-entering the same session must not deadlock against itself."""
    lock = tmp_path / "l"
    lock.write_text(str(os.getpid()))
    assert run_alone.current_holder(lock) is None


def test_an_unreadable_or_empty_lock_is_not_a_holder(tmp_path):
    lock = tmp_path / "l"
    lock.write_text("   ")
    assert run_alone.current_holder(lock) is None
    assert run_alone.current_holder(tmp_path / "missing") is None


# ── REPO LEVEL ──────────────────────────────────────────────────────────────

def test_the_lock_is_keyed_on_the_shared_git_directory_not_the_worktree():
    """Eighty worktrees of one repo must not get eighty locks.

    `--git-common-dir` is the same path from every checkout; `--git-dir` is not.
    Keying on the latter would let every worktree call itself alone.
    """
    shared = run_alone.common_git_dir()
    assert shared is not None and shared.is_dir(), shared
    assert run_alone.repo_lock_path() == shared / run_alone.REPO_LOCK_NAME
    # The same answer from another checkout of the same repository.
    others = [r for r in run_alone.worktree_roots()
              if r.is_dir() and r != pathlib.Path.cwd()]
    assert others, "no sibling worktree to compare against"
    assert run_alone.common_git_dir(others[0]) == shared


def test_a_pytest_invocation_is_told_apart_from_a_mention_of_pytest():
    """The guard refuses a whole suite on this answer, so a loose match is a
    false kill: it would name a shell that has already exited.

    The capital P case is not hypothetical. macOS runs
    `Python.app/Contents/MacOS/Python`, and a lowercase-only test matched
    nothing on this machine — the guard passed forever and the control caught
    it, not the reading.
    """
    macos = ("/opt/homebrew/Cellar/python@3.14/3.14.7/Frameworks/"
             "Python.framework/Versions/3.14/Resources/Python.app/Contents/"
             "MacOS/Python -m pytest gauntlet/boundary/tests -q")
    assert run_alone.is_pytest_invocation(macos)
    assert run_alone.is_pytest_invocation("/usr/local/bin/pytest tests/")
    assert run_alone.is_pytest_invocation("python3 -m pytest x.py")

    assert not run_alone.is_pytest_invocation("echo pytest")
    assert not run_alone.is_pytest_invocation("grep -rn pytest .")
    assert not run_alone.is_pytest_invocation("python3 -c 'print(1)'")
    assert not run_alone.is_pytest_invocation("")
    # The wrapper shell that was ASKED to run pytest is not pytest. It exits
    # while the run continues, so refusing on it names a dead pid.
    assert not run_alone.is_pytest_invocation(
        "/bin/zsh -c 'cd somewhere && python3 -m pytest tests/'")


def test_the_scan_excludes_our_own_process_group_and_not_merely_our_pid():
    """The conftest calling this runs INSIDE pytest, and xdist adds workers.

    Counting either would make the guard refuse its own session every time,
    which is the shape where a guard becomes the outage.
    """
    ours = os.getpgid(os.getpid())
    mine = [pid for pid, command in run_alone._cmdlines().items()
            if run_alone.is_pytest_invocation(command)
            and _same_group(pid, ours)]
    assert mine, "this test runs under pytest, so at least one must be ours"
    found = run_alone.foreign_pytest()
    assert found is None or found[0] not in mine


def _same_group(pid, ours):
    try:
        return os.getpgid(pid) == ours
    except OSError:
        return False
