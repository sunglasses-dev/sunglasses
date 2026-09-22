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
