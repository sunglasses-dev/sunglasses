"""Stopping a process group, including the part that outlives its leader.

T8.R12: process groups for upstream and workers; kill and reap the group EVEN
WHEN THE LEADER EXITED. T7.R2: SIGTERM then SIGKILL, descendants included.

That first clause is the whole reason this is a module rather than two lines
inside teardown. Killing by the leader's pid does nothing once the leader is
gone, and its children carry on holding the sockets and the payloads the
teardown exists to stop. A leader that spawns a child and exits immediately is
not an exotic case: it is what a shell wrapper does, and what `npx` does, and
those are the two most common ways an MCP server gets launched.

Signalling the GROUP is what survives that, because the group outlives the
leader and the descendants are in it.
"""
from __future__ import annotations

import errno
import os
import signal
import time


def _group_of(pid):
    """The process group to signal, falling back to the pid's own group.

    `getpgid` fails once the process is fully reaped, and by then the group is
    usually gone with it. The pid is used as the group id in that case because a
    caller that started the child with `start_new_session=True` made it the
    leader, so the two are the same number.
    """
    try:
        return os.getpgid(pid)
    except OSError:
        return pid


def _signal_group(pgid, sig):
    """Signal a whole group, treating "already gone" as success.

    ESRCH means nothing is there to signal, which is the state this function is
    trying to reach. Raising on it turns a completed teardown into a failed one,
    and T7.R2 runs this on paths where the group may well have exited already.
    """
    try:
        os.killpg(pgid, sig)
        return True
    except OSError as failed:
        if failed.errno in (errno.ESRCH, errno.EPERM):
            return False
        raise


def _reap(handle):
    """Collect the child through the handle that OWNS it, or not at all.

    T8.R12 says kill and reap, and the first version of this called
    `os.waitpid(pid, WNOHANG)` directly. That reaps, and it also STEALS the exit
    status from the `subprocess.Popen` the caller is holding, which then reports
    returncode 0 for a process that exited 7 and `poll() is None` for one that is
    already gone. The proxy would have misreported every upstream exit code as a
    clean zero, which is worse than the zombie it was avoiding: a wrong status in
    a receipt is evidence, and an uncollected child is housekeeping.

    Two of the tests written from the rows caught it, which is the argument for
    writing them first: both assert on the caller's handle after the stop, which
    is exactly where the theft shows.

    So the child is reaped through its owner when one is given, and otherwise is
    left alone. A process we did not start is not ours to collect; signalling the
    group still stops it, and the OS reparents what remains.
    """
    if handle is None:
        return
    try:
        handle.poll()
    except OSError as failed:                              # pragma: no cover
        if failed.errno != errno.ECHILD:
            raise


def _collect(handle, timeout=1.0):
    """The FINAL reap, which waits instead of polling.

    `poll()` answers "has it been collected yet" and the answer can be no for a
    short while after the group already looks empty, because the group losing
    its last member and the wait status becoming available are not the same
    instant. Polling there reported the group stopped while the caller's handle
    still said the child was running, which is a postcondition that is true a
    few milliseconds after it is claimed, and that is not true.

    Bounded, because this runs inside teardown and a supervisor that can block
    for ever has replaced one hang with another.
    """
    if handle is None:
        return
    try:
        handle.wait(timeout=timeout)
    except Exception:                                      # pragma: no cover
        # A timeout here means the status is not available yet. The group is
        # already gone, so this is housekeeping rather than a failure, and it is
        # not worth failing a completed teardown over.
        pass


def _group_alive(pgid):
    return _signal_group(pgid, 0)


def stop_group(pid, *, grace_ms=2000, poll_ms=25, handle=None):
    """SIGTERM the group, wait out the grace, then SIGKILL what is left.

    Both signals, in that order, and the order is not politeness. TERM alone
    leaves anything that traps it running for ever; KILL alone denies every
    upstream the chance to flush and exit cleanly, which is the difference
    between a shutdown and a crash for a server that is behaving.

    `handle` is the `subprocess.Popen` that owns this pid, when the caller has
    one. It is how the child is reaped without taking its exit status away from
    the object that is going to be asked for it.

    Returns True when the group is gone by the end, which is the postcondition
    a caller can act on rather than the fact that two signals were sent.
    """
    pgid = _group_of(pid)

    _signal_group(pgid, signal.SIGTERM)
    deadline = time.monotonic() + grace_ms / 1000
    while time.monotonic() < deadline:
        _reap(handle)
        if not _group_alive(pgid):
            # REAP AGAIN BEFORE RETURNING. The reap above ran a moment earlier
            # and the exit can land between the two calls, which is exactly what
            # happened: `stop_group` reported the group gone while the caller's
            # handle still said the child was running. The postcondition is not
            # "the group is empty", it is "the group is empty AND our child has
            # been collected", so the last thing before claiming it is a reap.
            _collect(handle)
            return True
        time.sleep(poll_ms / 1000)

    _signal_group(pgid, signal.SIGKILL)
    # KILL cannot be caught, but the exit is still not instantaneous and the
    # group is not gone until the kernel has finished with it.
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        _reap(handle)
        if not _group_alive(pgid):
            _collect(handle)
            return True
        time.sleep(poll_ms / 1000)
    _collect(handle)
    return not _group_alive(pgid)
