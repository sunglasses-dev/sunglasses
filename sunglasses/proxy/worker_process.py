"""T4.R1's worker, as a real child with real bounds.

Written against `tests/test_proxy_worker_process.py`, committed first.

The engine ran in the proxy's own process until now, which meant T8.R4's kill
on deadline and T8.R7's stdout bound had nothing to apply to. Nothing was
released by a hanging or flooding scan, so the direction was safe, but a bound
you cannot enforce is not a bound.

Everything here is about a scan that misbehaves.

THE DEADLINE IS A KILL. A worker past its clock still holds a CPU and a pipe,
and a runner that stops reading and returns leaves it there. The child gets its
own process group and the group is signalled, TERM then KILL after the grace,
which is the same shape serve.py uses on the upstream and for the same reason:
TERM alone leaves anything that traps it running for ever.

THE STDOUT BOUND IS ENFORCED WHILE READING. Not measured afterwards. Reading a
gigabyte to find out it was over a megabyte performs the fault in the act of
checking for it, so the reader stops at the limit and kills the group.

EXACTLY ONE COMPLETION. A worker that prints two results has answered twice,
and taking either one lets the scan choose which verdict gets settled. Silence
and rubbish are faults for the same reason: neither is a verdict.

And no fault carries the child's own words. Once a worker is reading peer
bytes its stdout is peer-adjacent, and a traceback is the most natural thing
for it to print.
"""
from __future__ import annotations

import json
import os
import select
import subprocess
import threading
import time

from . import bounds, supervisor, worker

STATUS_COMPLETE = "complete"
STATUS_EXCEPTION = "exception"
STATUS_DEADLINE = "deadline"

# WHY A CAUSE EXISTS BESIDE THE STATUS. Three operationally different failures
# reached the client as one word. A worker that DIED says look at the host; a
# worker that printed something unusable says look at the worker; a worker whose
# output did not fit the contract says the worker and this proxy disagree. The
# status stays `exception` for all three -- it is the client's contract and
# nothing here changes it -- and the cause is evidence for an operator.
#
# `schema_invalid` is NOT defined here on purpose. It cannot be: at `_fault`
# time the result has not been validated yet, and validation happens in `route`
# after `worker.validate`. A single enum in one module would have one value
# that this file could never emit, and nobody would notice, because an unset
# cause and an absent one look identical in a receipt.
CAUSE_CRASHED = "crashed"
CAUSE_MALFORMED_OUTPUT = "malformed_output"

DECISION_REVIEW = "review"

# THE STARTUP BUDGET IS NOT THE SCAN'S. Loading the engine costs ~1.5 s
# (measured 9-23 on an M3 Max: `SunglassesEngine()` 1,512 ms, a warm scan
# 0.6 ms), so a child spawned per scan spent ~80% of T8.R4's 2,000 ms before it
# read a byte -- and on a slower machine every message would be a deadline.
# A spare loads BEFORE it is given work and says so on a separate pipe; the
# scan's clock starts at the payload write. Waiting for a spare that is still
# loading is bounded HERE, separately, and a spare that never gets ready is
# killed and the item faults -- it is never handed a scan.
STARTUP_MS = 10_000
READY_ENV = "SUNGLASSES_WORKER_READY_FD"


def run(payload, *, binding, argv=None, timeout_ms=None, grace_ms=None,
        stdout_limit=None, child=None):
    """Spawn the worker, feed it the payload, and bound what comes back.

    `child` is an already-running worker (a warm spare from `ProcessScan`).
    Everything after the spawn is identical: the deadline, the stdout bound and
    the kill all apply to it the same way, and the clock starts at the write.
    """
    timeout_ms = bounds.INSPECTION_MS if timeout_ms is None else timeout_ms
    grace_ms = bounds.KILL_GRACE_MS if grace_ms is None else grace_ms
    stdout_limit = (bounds.WORKER_STDOUT_BYTES if stdout_limit is None
                    else stdout_limit)
    argv = argv or default_argv()

    if child is None:
        child = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=True)

    collected: dict = {}

    def collect():
        try:
            collected["out"] = _read_bounded(child.stdout, stdout_limit)
        except _TooMuch:
            collected["over"] = True
        except Exception:
            collected["broken"] = True

    # DELIVERY IS INSIDE THE DEADLINE (ASTRA worker-design r1, R1). The write
    # used to come first and the clock after it, so a child that stopped
    # draining stdin -- handed an admitted payload bigger than the pipe -- held
    # this thread in `write` with the kill below unreachable, and a slow drain
    # was then given a fresh full budget. One absolute deadline now exists
    # before a byte is written, the write runs on its own thread, and this
    # thread only ever waits on the clock.
    data = json.dumps(payload).encode("utf-8")
    deadline = time.monotonic() + timeout_ms / 1000.0

    def deliver():
        try:
            child.stdin.write(data)
            child.stdin.close()
        except (OSError, ValueError):
            # EPIPE from a child that answered without reading it all, or the
            # group stopped under us. Neither is a result; the reader decides.
            pass

    reader = threading.Thread(target=collect, daemon=True)
    writer = threading.Thread(target=deliver, daemon=True)
    reader.start()
    writer.start()

    # The READER is what is joined: an overflow ends it at once, so the stdout
    # bound still stops a flood mid-delivery rather than after it.
    reader.join(timeout=max(0.0, deadline - time.monotonic()))
    timed_out = reader.is_alive()
    if not timed_out and not collected.get("over"):
        # EOF IS NOT EXIT. The reader finishes when the child closes stdout,
        # and interpreter teardown sits between that and the process ending.
        # Deciding on `poll()` at that instant recorded a complete, on-time
        # answer as a DEADLINE and threw it away (20/20 with a child whose exit
        # trailed its EOF by 50 ms). So wait for the exit -- inside the SAME
        # budget, so a child that answers and then stays is still killed at the
        # deadline. A flood is not waited on: it will never exit by itself.
        try:
            child.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
    if timed_out or collected.get("over"):
        # Both faults end the same way and for the same reason: the child is
        # still there. Stopping the GROUP rather than the pid catches anything
        # it spawned, which is T8.R12 read the same way serve.py reads it.
        supervisor.stop_group(child.pid, grace_ms=grace_ms, handle=child)
        # The group is gone, so a blocked write has had its EPIPE. Join the
        # writer BEFORE closing stdin from here: BufferedWriter.close takes the
        # lock a blocked write holds, and closing first would put this thread
        # back behind the very write the deadline exists to escape.
        writer.join(timeout=1.0)
        _close_stdin(child, writer)
        reader.join(timeout=1.0)
        return _fault(binding,
                      STATUS_EXCEPTION if collected.get("over")
                      else STATUS_DEADLINE,
                      # Over the cap is the worker saying too much, which is its
                      # output being wrong. A deadline gets NO cause: "still
                      # running when time ran out" is already the whole fact.
                      CAUSE_MALFORMED_OUTPUT if collected.get("over") else None)

    # The child has exited, so the write has finished or had its EPIPE. Close
    # our end either way: a writer stopped by EPIPE leaves it open, and a
    # long-lived proxy would leak one descriptor per scan.
    writer.join(timeout=max(0.0, deadline - time.monotonic()))
    _close_stdin(child, writer)

    if collected.get("broken"):
        # The read failed, which means the child stopped being there while we
        # were reading it. That is the host's problem, not the worker's logic.
        return _fault(binding, STATUS_EXCEPTION, CAUSE_CRASHED)
    return _parse(collected.get("out", b""), binding)


def _close_stdin(child, writer):
    """Close the parent's end, but never while the writer still holds it: a
    close taken behind a blocked write would block with it."""
    if writer.is_alive():
        return
    try:
        child.stdin.close()
    except (OSError, ValueError):
        pass


def default_argv():
    import sys
    return [sys.executable, "-m", "sunglasses._proxy_worker"]


class _TooMuch(Exception):
    """The child went past T8.R7 while we were still reading."""


def _read_bounded(stream, limit):
    """Stop AT the limit. One byte over is already one byte too many read."""
    chunks, total = [], 0
    while True:
        chunk = stream.read1(65536) if hasattr(stream, "read1") else stream.read(65536)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > limit:
            raise _TooMuch()
        chunks.append(chunk)


def _parse(out, binding):
    lines = [line for line in out.splitlines() if line.strip()]
    if len(lines) != 1:
        # Zero is silence and two is a choice. Neither is a verdict.
        return _fault(binding, STATUS_EXCEPTION, CAUSE_MALFORMED_OUTPUT)
    try:
        value = json.loads(lines[0].decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return _fault(binding, STATUS_EXCEPTION, CAUSE_MALFORMED_OUTPUT)
    if not isinstance(value, dict):
        return _fault(binding, STATUS_EXCEPTION, CAUSE_MALFORMED_OUTPUT)
    # THE CHILD'S BINDING, AS THE CHILD SAID IT. This used to be
    # `dict(value, binding=dict(binding))`: the parent stamped its own binding
    # over the answer, so `worker.validate` compared the parent with itself and
    # a child answering about ANOTHER item was accepted as this one's result
    # (found by T10, 9-23; measured through the route: another item's `allow`
    # forwarded this call). Faults above still carry the parent's binding --
    # those are ours, built here, about the item we asked about.
    return value


def _fault(binding, status, cause=None):
    """A fault is a worker RESULT, so it carries the binding it was asked
    about. One bound to nothing is another item's answer under T4.R2, and it
    carries nothing the child said.

    `cause` is optional because a DEADLINE has no cause to add: the status
    already says the child was still running and got its group stopped, which
    is a different fact from anything below.
    """
    fault = {"binding": dict(binding), "accepted": False, "status": status,
             "inspection_complete": False, "decision": DECISION_REVIEW,
             "inspected_utf8_bytes": 0, "observed_content_bytes": 0,
             "elapsed_ms": 0, "findings": []}
    if cause is not None:
        fault["detector_status"] = cause
    # A LocalFault, so the route can tell a cause WE assigned from one a child
    # printed; see worker.LocalFault. `_parse` returns plain dicts on purpose.
    return worker.LocalFault(fault)


def _spawn(argv):
    """A child that will say `R` on its own pipe once the engine is loaded."""
    ready_r, ready_w = os.pipe()
    env = dict(os.environ)
    env[READY_ENV] = str(ready_w)
    try:
        child = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=True,
            pass_fds=(ready_w,), env=env)
    finally:
        os.close(ready_w)
    return child, ready_r


def _await_ready(ready_r, timeout_ms):
    """True only on the child's `R`. EOF (it died loading) and silence past the
    budget are both False; the caller kills it either way."""
    try:
        readable, _, _ = select.select([ready_r], [], [], timeout_ms / 1000.0)
        return bool(readable) and os.read(ready_r, 1) == b"R"
    finally:
        os.close(ready_r)


class ProcessScan:
    """The route's `scan=` through a real child, with T8.R4 and T8.R7 applied.

    ONE WARM SPARE. Each scan takes the spare and a replacement starts loading
    at once, so the next scan normally finds it ready. When it does not -- two
    directions at once, or back-to-back scans -- the scan waits for readiness
    under STARTUP_MS, never under its own deadline, and a spare that is not
    ready by then is killed and the item faults.
    """

    def __init__(self, *, argv=None, timeout_ms=None, grace_ms=None,
                 stdout_limit=None, startup_ms=None):
        self.argv = argv or default_argv()
        self.timeout_ms = bounds.INSPECTION_MS if timeout_ms is None else timeout_ms
        self.grace_ms = bounds.KILL_GRACE_MS if grace_ms is None else grace_ms
        self.stdout_limit = stdout_limit
        self.startup_ms = STARTUP_MS if startup_ms is None else startup_ms
        self._lock = threading.Lock()
        self._closed = False
        self._spare = _spawn(self.argv)

    def _take(self):
        with self._lock:
            spare = self._spare
            self._spare = None if self._closed else _spawn(self.argv)
        return spare

    def __call__(self, params, *, channel, binding, content_bytes):
        spare = self._take()
        if spare is None:
            # close() already ran: the worker this call needed does not exist.
            # Reachable only after teardown. crashed, from the three causes
            # (T9 ruling 9-23): a missing process is the host's side.
            return _fault(binding, STATUS_EXCEPTION, CAUSE_CRASHED)
        child, ready_r = spare
        if not _await_ready(ready_r, self.startup_ms):
            supervisor.stop_group(child.pid, grace_ms=self.grace_ms,
                                  handle=child)
            # It died loading or never said ready: a process failure the
            # parent observed, never a scan result. crashed.
            return _fault(binding, STATUS_EXCEPTION, CAUSE_CRASHED)
        return run({"params": params, "channel": channel, "binding": binding,
                    "content_bytes": content_bytes},
                   binding=binding, child=child, timeout_ms=self.timeout_ms,
                   grace_ms=self.grace_ms, stdout_limit=self.stdout_limit)

    def close(self):
        """Kill the waiting spare. Idempotent; the proxy calls it on teardown,
        because `exit_process` leaves through `os._exit` and atexit never runs."""
        with self._lock:
            spare, self._spare, self._closed = self._spare, None, True
        if spare is not None:
            child, ready_r = spare
            try:
                os.close(ready_r)
            except OSError:
                pass
            supervisor.stop_group(child.pid, grace_ms=self.grace_ms,
                                  handle=child)
