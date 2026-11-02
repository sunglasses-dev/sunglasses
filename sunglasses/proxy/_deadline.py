"""One clock for a run, and the only places in the doctor's route launcher that wait on it.

A `Clock` is one absolute monotonic end. Every wait the route launcher makes goes through
`take()`, which is the smaller of the wait's own bound and what is left of the clock, never
below zero. The few functions here that block (`sleep`, `wait`, `join`, `run`) each call
`take()` first and hand only its result to the operating system, so a wait cannot be longer
than the clock. A test reads `route_launch.py` and this file and fails on any other way to
block (see `tests/proxy/test_route_launch.py`).

What this does not do: a single system call that does not return (one `listdir`, one `read`)
cannot be interrupted from here. The loops around those calls check the clock between steps.
"""
from __future__ import annotations

import subprocess
import time

# How long a process that was killed is waited for before it is given up on.
REAP_S = 2.0


class Clock:
    """One allowance, as an end on the monotonic clock. `now` can be replaced in a test."""

    def __init__(self, seconds, now=time.monotonic):
        self._now = now
        self._end = now() + seconds

    def left(self) -> float:
        return max(0.0, self._end - self._now())

    def spent(self) -> bool:
        return self.left() <= 0.0

    def take(self, bound, reserve=0.0) -> float:
        """`bound`, or what is left once `reserve` is set aside, whichever is smaller."""
        return max(0.0, min(bound, self.left() - reserve))

    def sub(self, bound, reserve=0.0):
        """A clock that ends `bound` from now or with this one, whichever is first."""
        return Clock(self.take(bound, reserve), now=self._now)

    def sleep(self, bound):
        pause = self.take(bound)
        time.sleep(pause)

    def wait(self, proc, bound):
        """The exit code of `proc`, or None if it has not ended in time."""
        limit = self.take(bound)
        try:
            return proc.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            return None

    def join(self, thread, bound):
        limit = self.take(bound)
        thread.join(limit)

    def run(self, argv, bound, env):
        """(exit code, text output) of a command that ends in time, else None.

        The command is started here and killed here, so the wait that follows the kill is
        one of ours and has a limit too (the standard library's `run` waits without one).
        """
        limit = self.take(bound)
        if limit <= 0.0:
            return None
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True, env=env)
        except (OSError, ValueError):
            return None
        try:
            output, _ = proc.communicate(timeout=limit)
        except subprocess.TimeoutExpired:
            proc.kill()
            self.wait(proc, REAP_S)
            return None
        finally:
            try:
                proc.stdout.close()
            except (OSError, ValueError):
                pass
        return proc.returncode, output
