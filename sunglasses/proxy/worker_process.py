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
                      else STATUS_DEADLINE)

    if collected.get("broken"):
        return _fault(binding, STATUS_EXCEPTION)
    return _parse(collected.get("out", b""), binding, raw=raw)


def default_argv():
    import sys
    return [sys.executable, "-m", "sunglasses.proxy.scan_worker"]


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
        return _fault(binding, STATUS_EXCEPTION)
    try:
        value = json.loads(lines[0].decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return _fault(binding, STATUS_EXCEPTION)
    if not isinstance(value, dict):
        return _fault(binding, STATUS_EXCEPTION)
    return value if raw else dict(value, binding=dict(binding))


def _fault(binding, status):
    """A fault is a worker RESULT, so it carries the binding it was asked
    about. One bound to nothing is another item's answer under T4.R2, and it
    carries nothing the child said."""
    return {"binding": dict(binding), "accepted": False, "status": status,
            "inspection_complete": False, "decision": DECISION_REVIEW,
            "inspected_utf8_bytes": 0, "observed_content_bytes": 0,
            "elapsed_ms": 0, "findings": []}
