"""One run at a time — the decision, in a module anything can import.

Deliberately NOT inside `conftest.py`. A conftest is importable by pytest and
awkward for everything else, so decision logic living there can only be tested
by running the thing it guards. The guard's own rows could not import it
(`conftest` pulls the exam scaffold in at import time), which is how a guard
ends up with no tests at all.

WHY THE GUARD EXISTS. 2026-09-22: this suite was reported FLAKY on four runs
that returned 15, 17, 16 and 20 failures. It is not flaky — five sequential runs
of an untouched tree returned 15 every time with identical name sets and ZERO
movers. The spread came from running two and three pytest sessions at once:
these tests spawn real subprocesses, bind real files and drive timed barriers.
Concurrent runs invent failures in one direction and would hide real ones in the
other, so a number produced beside another run is VOID, not merely noisy.

The damage was not wasted runs. A false finding about the harness was written
up and reported. A rule in a document is read by whoever already knows it; this
refuses.

NOT `pgrep`. A pgrep for "pytest" matches the process doing the pgrep, and a
guard that reads its own command line measures itself (Sep-08: a wait loop that
never exited for exactly that reason). A pid in a lock file is checkable without
that hazard — it either names a live process or it does not.
"""
from __future__ import annotations

import os
import pathlib

LOCK = pathlib.Path(__file__).resolve().parent / ".suite-in-progress.lock"


def holder_alive(pid: int) -> bool:
    """True when `pid` names a live process.

    A STALE lock is reclaimed, never obeyed: a crashed run leaves its lock
    behind, and a guard that treats that as a live holder locks the suite out
    permanently — the failure mode where the guard becomes the outage.
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True            # exists, owned by another user
    return True


def current_holder(lock: pathlib.Path | None = None) -> int | None:
    """The live pid holding the suite, or None. Unreadable == not held."""
    lock = lock or LOCK
    try:
        pid = int(lock.read_text().strip() or 0)
    except (OSError, ValueError):
        return None
    if pid and pid != os.getpid() and holder_alive(pid):
        return pid
    return None
