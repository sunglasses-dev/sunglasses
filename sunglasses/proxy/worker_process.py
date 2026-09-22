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
import subprocess
import threading

from . import bounds, supervisor

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


def run(payload, *, binding, argv=None, timeout_ms=None, grace_ms=None,
        stdout_limit=None, raw=False):
    """Spawn the worker, feed it the payload, and bound what comes back."""
    timeout_ms = bounds.INSPECTION_MS if timeout_ms is None else timeout_ms
    grace_ms = bounds.KILL_GRACE_MS if grace_ms is None else grace_ms
    stdout_limit = (bounds.WORKER_STDOUT_BYTES if stdout_limit is None
                    else stdout_limit)
    argv = argv or default_argv()

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

    reader = threading.Thread(target=collect, daemon=True)
    reader.start()
    try:
        child.stdin.write(json.dumps(payload).encode("utf-8"))
        child.stdin.close()
    except OSError:
        pass

    reader.join(timeout=timeout_ms / 1000.0)
    timed_out = reader.is_alive() or child.poll() is None
    if timed_out or collected.get("over"):
        # Both faults end the same way and for the same reason: the child is
        # still there. Stopping the GROUP rather than the pid catches anything
        # it spawned, which is T8.R12 read the same way serve.py reads it.
        supervisor.stop_group(child.pid, grace_ms=grace_ms, handle=child)
        reader.join(timeout=1.0)
        return _fault(binding,
                      STATUS_EXCEPTION if collected.get("over")
                      else STATUS_DEADLINE,
                      # Over the cap is the worker saying too much, which is its
                      # output being wrong. A deadline gets NO cause: "still
                      # running when time ran out" is already the whole fact.
                      CAUSE_MALFORMED_OUTPUT if collected.get("over") else None)

    if collected.get("broken"):
        # The read failed, which means the child stopped being there while we
        # were reading it. That is the host's problem, not the worker's logic.
        return _fault(binding, STATUS_EXCEPTION, CAUSE_CRASHED)
    return _parse(collected.get("out", b""), binding, raw=raw)


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


def _parse(out, binding, *, raw=False):
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
    return value if raw else dict(value, binding=dict(binding))


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
    return fault
