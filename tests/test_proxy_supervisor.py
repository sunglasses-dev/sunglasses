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
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


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

    supervisor.stop_group(stubborn.pid, grace_ms=250)

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
    supervisor.stop_group(child.pid, grace_ms=250)
    assert child.poll() is not None, "the child was killed but never reaped"
