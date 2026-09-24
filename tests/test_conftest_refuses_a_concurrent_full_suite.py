"""The scanner suite refuses to start a FULL run beside another one.

THE CONTROL IS A REAL FOREIGN PYTEST, NOT A MOCK. `foreign_pytest()` returns
`None` when it finds nothing, and `None` is exactly what a broken detector
returns too -- a wrong `ps` invocation, a changed command-line shape, a missing
`lsof` all produce a quiet `None` and a guard that never fires. So the control
STARTS a real pytest in its own process group, against this repository, and
requires the detector to NAME it. Without that, this file would pass on a
machine where the guard does nothing at all.
"""
import os
import pathlib
import subprocess
import sys
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from run_alone import (current_holder, foreign_pytest,  # noqa: E402
                       is_pytest_invocation, repo_lock_path, worktree_roots)

# BY PATH, deliberately. `import conftest` resolves to tests/conftest.py, not
# the root one, so the obvious import silently grades a different file.
import importlib.util  # noqa: E402
_spec = importlib.util.spec_from_file_location("_root_conftest", ROOT / "conftest.py")
_root_conftest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_root_conftest)
_run_is_the_whole_tree = _root_conftest._run_is_the_whole_tree


class _Config:
    """The two fields the decision reads, and nothing else."""
    def __init__(self, args, rootdir, keyword=None, markexpr=None):
        self.args = args
        self.rootdir = rootdir
        self.option = type("O", (), {"keyword": keyword, "markexpr": markexpr})()


def test_a_full_run_is_recognised_and_a_targeted_one_is_not():
    root = str(ROOT)
    assert _run_is_the_whole_tree(_Config([], root))
    assert _run_is_the_whole_tree(_Config(["tests"], root))
    assert _run_is_the_whole_tree(_Config([str(ROOT / "tests")], root))
    # Targeted, and each of these is how a person actually iterates.
    assert not _run_is_the_whole_tree(_Config(["tests/test_patterns.py"], root))
    assert not _run_is_the_whole_tree(
        _Config(["tests/test_patterns.py::test_one"], root))
    assert not _run_is_the_whole_tree(_Config(["tests"], root, keyword="poison"))
    assert not _run_is_the_whole_tree(_Config(["tests"], root, markexpr="slow"))


@pytest.fixture
def a_real_foreign_pytest(tmp_path):
    """A pytest running against this repo, in ITS OWN process group."""
    probe = tmp_path / "test_probe_for_the_guard.py"
    probe.write_text("import time\ndef test_hold(): time.sleep(20)\n")
    proc = subprocess.Popen(
        [sys.executable, "-m", "pytest", str(probe), "-q"],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)          # its own group, like another session
    try:
        yield proc
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), 15)
        except OSError:
            proc.terminate()
        proc.wait(timeout=30)


def test_the_detector_names_a_real_foreign_pytest(a_real_foreign_pytest):
    """The positive. A detector that always returns None must fail here."""
    # WHAT THIS CAN AND CANNOT ASSERT, stated rather than papered over.
    # `foreign_pytest` returns the LOWEST-PID candidate, so on a machine where
    # a teammate's longer-running suite is already live it will name THAT one,
    # not this child. The first version of this row asserted only "not None"
    # and passed for exactly that reason -- it would have passed with the spawn
    # deleted. So the row proves two things separately:
    #
    #   1. the detector answers at all while a real foreign pytest exists, and
    #   2. the detector's own PREDICATES match THIS child specifically,
    #
    # and (2) is what makes it a control rather than a coincidence.
    deadline = time.monotonic() + 25
    answered = None
    while time.monotonic() < deadline:
        answered = foreign_pytest(ROOT)
        if answered is not None:
            break
        time.sleep(0.5)
    assert answered is not None, (
        "a real pytest is running against this repository from another process "
        "group and the detector reported NOTHING -- an empty answer from a "
        "detector that cannot see is indistinguishable from an idle machine.")

    child = a_real_foreign_pytest.pid
    command = subprocess.run(["ps", "-o", "command=", "-p", str(child)],
                             capture_output=True, text=True).stdout.strip()
    assert command, f"the probe pid {child} is not in the process table"
    assert is_pytest_invocation(command), (
        f"the detector would not classify this child as a pytest at all, so it "
        f"could never name it: {command[:200]}")
    roots = worktree_roots(ROOT)
    assert roots, "no worktree roots resolved, so nothing could ever match"
    assert any(ROOT == r or str(ROOT).startswith(str(r)) for r in roots), (
        f"this repository is not among the roots the detector searches: {roots}")


def test_the_detector_does_not_name_our_own_session():
    """The other direction, or the guard refuses every run including this one."""
    ours = foreign_pytest(ROOT)
    if ours is not None:
        assert ours[0] != os.getpid(), ours
        assert os.getpgid(ours[0]) != os.getpgid(os.getpid()), ours


def test_a_live_lock_is_seen_and_a_dead_one_is_not(tmp_path,
                                                   a_real_foreign_pytest):
    """A holder pid must be LIVE. A stale lock file must not park the repo."""
    lock = tmp_path / ".suite-in-progress.lock"
    lock.write_text(str(a_real_foreign_pytest.pid))
    assert current_holder(lock) == a_real_foreign_pytest.pid
    # A pid that cannot be running: no live process, so no holder.
    lock.write_text("999999")
    assert current_holder(lock) is None, (
        "a stale lock file would park every full run on this repository until "
        "someone deleted it by hand")
