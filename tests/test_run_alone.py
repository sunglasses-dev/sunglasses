"""The repository wide run-alone guard: what it refuses, and what it must not.

RED FIRST, and the positive matters more than the negative here. A guard that
returns "nothing found" is indistinguishable from a guard that never looked,
and this one shipped twice in a state where it could never fire: once matching
the wrapper shell instead of the run, once testing `startswith("python")`
against macOS's `Python.app/Contents/MacOS/Python`. Both times the code read
correctly. Only a real foreign pytest, put in front of it, told the truth.

So `test_a_real_foreign_pytest_is_seen` starts an actual pytest in another
worktree and requires the scan to name it. Nothing here asserts on a bare None.
"""
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import run_alone  # noqa: E402


def test_a_live_pid_is_reported_alive():
    assert run_alone.holder_alive(os.getpid()) is True


def test_a_dead_pid_is_not_a_holder(tmp_path):
    """A stale lock is RECLAIMED, never obeyed.

    A crashed run leaves its lock behind. A guard that treats that as a live
    holder locks every suite out permanently, which is the failure where the
    guard becomes the outage.
    """
    done = subprocess.run([sys.executable, "-c", "pass"])
    assert done.returncode == 0
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()

    lock = tmp_path / "suite.lock"
    lock.write_text(str(dead.pid))
    assert run_alone.holder_alive(dead.pid) is False
    assert run_alone.current_holder(lock) is None


def test_an_unreadable_lock_is_not_a_holder(tmp_path):
    lock = tmp_path / "suite.lock"
    assert run_alone.current_holder(lock) is None          # absent
    lock.write_text("not a pid")
    assert run_alone.current_holder(lock) is None          # garbage
    lock.write_text("")
    assert run_alone.current_holder(lock) is None          # empty


def test_our_own_pid_in_the_lock_is_not_a_holder(tmp_path):
    """Otherwise a session refuses to continue past its own lock."""
    lock = tmp_path / "suite.lock"
    lock.write_text(str(os.getpid()))
    assert run_alone.current_holder(lock) is None


def test_the_lock_is_keyed_on_the_shared_git_directory_not_the_worktree():
    """Every worktree of one repository must take the SAME lock.

    `--git-common-dir` is that shared path; `--git-dir` is per worktree. Keying
    on the latter would let eighty checkouts run eighty suites and let each one
    call itself alone.
    """
    shared = run_alone.common_git_dir(ROOT)
    assert shared is not None and shared.is_dir(), shared
    assert run_alone.repo_lock_path(ROOT) == shared / run_alone.REPO_LOCK_NAME

    # The same answer from anywhere inside the repository, which is the property
    # that makes it a repository key rather than a directory key. Asked from a
    # SIBLING WORKTREE at first, and that only holds on a machine that happens
    # to have one: a CI runner has exactly one checkout and the row failed there
    # for the environment rather than for the code.
    assert run_alone.common_git_dir(ROOT / "tests") == shared
    assert run_alone.common_git_dir(ROOT / "tools") == shared
    assert ROOT in run_alone.worktree_roots(ROOT), run_alone.worktree_roots(ROOT)


def test_a_pytest_invocation_is_told_apart_from_a_mention_of_pytest():
    """The guard refuses a whole suite on this answer.

    A loose match names the WRAPPER SHELL, which exits while the run it started
    carries on, so the refusal would cite a dead pid. The capital P case is not
    hypothetical: macOS runs `Python.app/Contents/MacOS/Python`, and a
    lowercase-only test matched nothing at all on this machine.
    """
    macos = ("/opt/homebrew/Cellar/python@3.14/3.14.7/Frameworks/Python.framework/"
             "Versions/3.14/Resources/Python.app/Contents/MacOS/Python "
             "-m pytest tests -q")
    assert run_alone.is_pytest_invocation(macos)
    assert run_alone.is_pytest_invocation("/usr/local/bin/pytest tests/")
    assert run_alone.is_pytest_invocation("python3 -m pytest x.py")
    assert run_alone.is_pytest_invocation("python3.14 -m pytest")

    assert not run_alone.is_pytest_invocation("")
    assert not run_alone.is_pytest_invocation("echo pytest")
    assert not run_alone.is_pytest_invocation("grep -rn pytest .")
    assert not run_alone.is_pytest_invocation("python3 -c 'print(1)'")
    assert not run_alone.is_pytest_invocation("vim tests/test_pytest_things.py")
    assert not run_alone.is_pytest_invocation(
        "/bin/zsh -c 'cd somewhere && python3 -m pytest tests/'")


def test_the_scan_excludes_our_own_process_group_and_not_merely_our_pid():
    """This test runs INSIDE pytest, and xdist would add workers besides.

    Excluding only `getpid()` would make every session refuse itself.
    """
    ours = os.getpgid(os.getpid())
    mine = [pid for pid, command in run_alone._cmdlines().items()
            if run_alone.is_pytest_invocation(command) and _group_of(pid) == ours]
    assert mine, "running under pytest, so at least one invocation must be ours"

    found = run_alone.foreign_pytest(ROOT)
    assert found is None or found[0] not in mine


def test_a_real_foreign_pytest_is_seen(tmp_path):
    """THE POSITIVE. Without it, every other answer here is unfalsifiable.

    A real pytest, in a real sibling worktree of this repository, from another
    process group. The scan must name that process — not the shell that started
    it, which is what the first version returned.
    """
    # THIS checkout, which every environment has. Requiring a sibling worktree
    # tested the machine's layout rather than the scan: a CI runner has one
    # checkout and there is nothing to find.
    elsewhere = ROOT

    sleeper = tmp_path / "test_sleeper.py"
    sleeper.write_text("import time\n\n\ndef test_sleeps():\n    time.sleep(30)\n")

    child = subprocess.Popen(
        [sys.executable, "-m", "pytest", str(sleeper), "-q", "-p", "no:cacheprovider"],
        cwd=str(elsewhere), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)
    try:
        # THE CHILD, by pid. "Some foreign pytest was found" would pass on a
        # process this test did not start, which proves nothing about whether
        # the scan can see the one in front of it.
        seen = None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            found = run_alone.foreign_pytest(ROOT)
            if found and found[0] == child.pid:
                seen = found
                break
            time.sleep(0.25)

        assert seen is not None, (
            f"pytest pid {child.pid} is running in {elsewhere} and the scan "
            "did not name it")
        assert run_alone.is_pytest_invocation(seen[1]), seen[1]
        assert "-m" in seen[1] and "pytest" in seen[1]
    finally:
        child.kill()
        child.wait()


def _group_of(pid):
    try:
        return os.getpgid(pid)
    except OSError:
        return None
