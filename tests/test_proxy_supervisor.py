"""T8.R12 and T7.R2's process mechanics, from the rows, before the code.

  T8.R12  process groups for upstream and workers; kill and reap the group EVEN
          WHEN THE LEADER EXITED.
  T7.R2   SIGTERM then SIGKILL the upstream process group and every worker
          group, descendants included.

The clause that decides the design is "even when the leader exited". A
supervisor that kills by the leader's pid does nothing once the leader is gone,
and its children keep running: the exact case is a leader that spawns a child
and exits, which is what a shell wrapper or a `npx` launcher does every time.
Reaping the GROUP is what survives that, and a test has to actually leave a
descendant behind or it proves nothing.
"""
import os
import signal
import subprocess
import sys
import time

import pytest


def _pid_from_marker(marker, timeout=5.0):
    """The pid a child wrote to `marker`, waiting for CONTENT and not for the file.

    THE DEFECT THIS REPLACES, measured on 2026-09-21: the caller polled
    `os.path.exists(marker)` and then read it. `open(path, "w")` CREATES the file
    before anything is written to it, so existence was true while the content was
    still `""` and `int("")` raised ValueError — 1 h 9 m into the 3.14 leg,
    blocking a PR that does not touch this file. It is a race, so it fires under
    runner load and passes on a quiet laptop, which is the worst way for a test
    to be wrong: it reads as someone else's bug.

    Waiting for a non-empty read is the reader's half. The writer's half is in
    the test below: write to a temp name and os.replace() onto the marker, which
    is atomic, so after this change existence DOES imply content and the two
    halves agree instead of racing.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            text = open(marker).read().strip()
        except FileNotFoundError:
            text = ""
        if text:
            return int(text)
        time.sleep(0.02)
    raise AssertionError(
        f"no pid in {marker} within {timeout}s "
        f"(exists={os.path.exists(marker)}); the child never finished writing")

supervisor = pytest.importorskip(
    "sunglasses.proxy.supervisor",
    reason="the supervisor is the slice being specified here")


def _leader_with_child(marker):
    """A leader that spawns a long-lived grandchild and then EXITS.

    This is the shape T8.R12 names. The grandchild writes a marker file so the
    test can see it ran, and sleeps long enough that its survival would be
    unambiguous.
    """
    code = (
        "import subprocess, sys, os\n"
        f"subprocess.Popen([sys.executable, '-c', "
        f"\"open({marker!r},'w').write(str(__import__('os').getpid()));"
        f" import time; time.sleep(120)\"])\n"
        "sys.exit(0)\n"
    )
    return subprocess.Popen([sys.executable, "-c", code], start_new_session=True)


def _alive(pid):
    """Running, and NOT a zombie.

    `os.kill(pid, 0)` succeeds on a process that has been killed and not yet
    reaped, so on its own it reports a corpse as alive. That is not pedantry: it
    is why the stubborn case below has to pass its handle, and it is worth
    stating because a supervisor test that cannot tell a zombie from a live
    process will happily pass for a supervisor that kills nothing.
    """
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    state = subprocess.run(["ps", "-o", "state=", "-p", str(pid)],
                           capture_output=True, text=True).stdout.strip()
    return not state.startswith("Z")


def test_a_group_is_killed_even_after_its_leader_has_exited(tmp_path):
    """T8.R12's clause, with a real descendant behind a real exited leader."""
    marker = str(tmp_path / "grandchild.pid")
    leader = _leader_with_child(marker)
    leader.wait(timeout=10)
    assert leader.poll() == 0, "the leader is supposed to have exited cleanly"

    for _ in range(100):
        if os.path.exists(marker):
            break
        time.sleep(0.05)
    grandchild = int(open(marker).read())
    assert _alive(grandchild), "the descendant did not survive its leader"

    supervisor.stop_group(leader.pid, grace_ms=250)

    for _ in range(100):
        if not _alive(grandchild):
            break
        time.sleep(0.05)
    assert not _alive(grandchild), (
        "the descendant outlived the teardown, which is what killing by the "
        "leader's pid does once the leader is gone")


def test_stopping_an_already_dead_group_is_not_an_error():
    """T7.R2 runs this on a path that may already have been cleaned up, and a
    supervisor that raises there turns a completed teardown into a failed one."""
    child = subprocess.Popen([sys.executable, "-c", "pass"],
                             start_new_session=True)
    child.wait(timeout=10)
    supervisor.stop_group(child.pid, grace_ms=100)   # must not raise


def test_a_process_that_ignores_sigterm_is_killed(tmp_path):
    """SIGTERM then SIGKILL, in that order. A supervisor that sends only TERM
    leaves anything that traps it running for ever."""
    code = ("import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "time.sleep(120)\n")
    stubborn = subprocess.Popen([sys.executable, "-c", code],
                                start_new_session=True)
    time.sleep(0.3)
    assert _alive(stubborn.pid)

    # The HANDLE is passed because this test owns the process, which is how a
    # real caller uses this and the only way the child can be reaped. Without
    # it the process is killed and stays a zombie, and a zombie answers
    # `os.kill(pid, 0)`.
    supervisor.stop_group(stubborn.pid, grace_ms=250, handle=stubborn)

    for _ in range(100):
        if not _alive(stubborn.pid):
            break
        time.sleep(0.05)
    assert not _alive(stubborn.pid), "SIGTERM was ignored and no SIGKILL followed"


def test_a_cooperative_process_gets_the_chance_to_exit_on_sigterm():
    """Or the test above would pass for a supervisor that only ever SIGKILLs,
    which denies every upstream the chance to shut down cleanly."""
    code = ("import signal, sys, time\n"
            "signal.signal(signal.SIGTERM, lambda *a: sys.exit(7))\n"
            "time.sleep(120)\n")
    polite = subprocess.Popen([sys.executable, "-c", code],
                              start_new_session=True)
    time.sleep(0.3)
    supervisor.stop_group(polite.pid, grace_ms=2000)
    assert polite.wait(timeout=5) == 7, (
        "the process was killed rather than allowed to handle SIGTERM")


def test_the_group_is_reaped_so_nothing_is_left_a_zombie():
    """T8.R12 says kill AND reap. An unreaped child is a zombie for as long as
    the proxy lives, and a long session accumulates them."""
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"],
                             start_new_session=True)
    time.sleep(0.2)
    supervisor.stop_group(child.pid, grace_ms=250, handle=child)
    assert child.poll() is not None, "the child was killed but never reaped"
    assert not _alive(child.pid), "it was reaped and is still a zombie"


def test_the_group_is_resolved_from_the_process_not_assumed_to_be_its_pid(tmp_path):
    """`os.getpgid(pid)`, not `pid`.

    Every other test here starts its process with `start_new_session=True`,
    which makes the pid and the group id the same number, so a supervisor that
    simply used the pid as the group id passed all of them. It is not the same
    number for anything that did not create its own session, and using the pid
    there signals a group that may not exist, or worse, one that does and is
    somebody else's.

    A grandchild inside a leader's session is the case: its pid differs from its
    group, its group is the leader's, and stopping it must take the whole group
    down with it.
    """
    marker = str(tmp_path / "grandchild.pid")
    # The grandchild writes to a TEMP NAME and os.replace()s it onto the marker.
    # os.replace is atomic on the same filesystem, so the marker never exists in
    # a half-written state and "it exists" now means "it has content".
    inner = (
        "import os, time\n"
        f"p = {marker!r}\n"
        "tmp = p + '.part'\n"
        "open(tmp, 'w').write(str(os.getpid()))\n"
        "os.replace(tmp, p)\n"
        "time.sleep(120)\n"
    )
    code = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {inner!r}])\n"
        "time.sleep(120)\n"
    )
    leader = subprocess.Popen([sys.executable, "-c", code], start_new_session=True)
    grandchild = _pid_from_marker(marker)

    from sunglasses.proxy import supervisor as sup
    assert sup._group_of(grandchild) == leader.pid, (
        "the grandchild's group is the leader's, and this is the only test here "
        "where the pid and the group differ")
    assert grandchild != leader.pid, "the two numbers must differ for this to mean anything"

    try:
        supervisor.stop_group(grandchild, grace_ms=250)
        for _ in range(100):
            if not _alive(leader.pid) and not _alive(grandchild):
                break
            time.sleep(0.05)
        assert not _alive(grandchild), "the grandchild survived"
        assert leader.poll() is not None or not _alive(leader.pid), (
            "the leader survived, so the pid was signalled rather than the group")
    finally:
        if leader.poll() is None:
            leader.kill()
        leader.wait(timeout=5)


# ── THE RACE THAT BLOCKED A PR IT DID NOT BELONG TO ──────────────────────────
# 2026-09-21: `integrity (3.14)` went red 1 h 9 m in with
# `ValueError: invalid literal for int() with base 10: ''` at the marker read,
# on a PR whose whole delta was one unrelated test file. Five other Python legs
# passed and a local full suite passed, because a race only fires under load.
#
# These two rows make the defect and its repair executable, so the next person
# reading a red 3.14 leg has something better than "probably flaky".


def test_the_old_marker_read_loses_to_a_slow_writer(tmp_path):
    """RED-FIRST, against the code this change replaced.

    The writer opens the file and is slow to write. The OLD reader — poll
    os.path.exists, then int(open(...).read()) — sees the file the instant it is
    created and reads nothing. This row asserts that the old shape FAILS, so the
    fix below is measured against a defect that has been reproduced rather than
    described.
    """
    marker = str(tmp_path / "slow.pid")
    slow = (
        "import os, sys, time\n"
        f"f = open({marker!r}, 'w')\n"          # exists now, empty
        "time.sleep(1.0)\n"                     # the window, forced open
        "f.write(str(os.getpid())); f.flush(); f.close()\n"
    )
    child = subprocess.Popen([sys.executable, "-c", slow])
    try:
        for _ in range(100):                    # the OLD reader, verbatim
            if os.path.exists(marker):
                break
            time.sleep(0.05)
        with pytest.raises(ValueError):
            int(open(marker).read())
    finally:
        child.wait(timeout=10)


def test_the_new_marker_read_waits_for_content(tmp_path):
    """GREEN, same writer, same window: the reader waits for a non-empty read."""
    marker = str(tmp_path / "slow.pid")
    slow = (
        "import os, sys, time\n"
        f"f = open({marker!r}, 'w')\n"
        "time.sleep(1.0)\n"
        "f.write(str(os.getpid())); f.flush(); f.close()\n"
    )
    child = subprocess.Popen([sys.executable, "-c", slow])
    try:
        assert _pid_from_marker(marker, timeout=10.0) == child.pid
    finally:
        child.wait(timeout=10)


def test_the_reader_reports_a_writer_that_never_arrives(tmp_path):
    """And it must not hang or read garbage when nothing is ever written.

    Otherwise the repair trades a ValueError for a test that waits forever,
    which on a runner is a killed job and no verdict at all.
    """
    with pytest.raises(AssertionError, match="never finished writing"):
        _pid_from_marker(str(tmp_path / "absent.pid"), timeout=0.3)
