"""The thin pass-through, and the three ways it could lie about a candidate.

This is the harness, not the product. Its job is to hold a message in either
direction, let the scanner decide, and then forward, replace or refuse. Three of
ASTRA's twelve seeds are aimed at THIS file rather than at any candidate, because
a mediator that deadlocks, guesses its way back into sync, or delivers a held
message after cancellation would report those as candidate results.

Three properties, each with a test that was red before this module existed:

1. THE DEADLINE BELONGS TO THE WORKER, NEVER THE EVENT LOOP. The scan runs in a
   killable child process. `sleep()` in the forwarding path would satisfy a naive
   timing assertion while making the proxy unable to answer anything else, so the
   test submits a second message DURING the hang and requires an answer.
2. AN UNPARSEABLE FRAME IS REFUSED, NOT RESYNCHRONISED. Guessing where a stream
   resumes is how a mediator forwards half of an attacker's message. The wire
   limit is checked on BYTES before any parse, because a limit applied after
   `json.loads` is not a limit.
3. A WATCHDOG FAILS THE HARNESS. If this file wedges, that is a harness fault and
   it must raise. A watchdog that merely stopped waiting would turn a broken
   harness into a scenario result, which is the whole failure mode being guarded.
"""
from __future__ import annotations

import enum
import json
import os
import signal
import subprocess
import threading
import time
import uuid

GATE2_WITHHELD_CODE = -32070
GATE2_WITHHELD = "GATE2_WITHHELD"
DEFAULT_WIRE_FRAME_LIMIT = 4 * 1024 * 1024
TERMINATION_GRACE_MS = 250

# The worker is a SUBPROCESS driven by argv, which is what the scenario package
# specifies: `["python3", "fault_worker.py", "hang"]`. An earlier draft forked a
# Python callable instead, and CPython warned that forking a multi-threaded
# process may deadlock in the child. Accepting a deadlock warning inside the one
# component whose job is to not deadlock would have been absurd, and the argv
# form is also what the real runs use, so the unit tests now exercise the same
# mechanism rather than a convenient stand-in.
#
# The child is put in its OWN PROCESS GROUP so termination reaches anything it
# spawned. Killing only the direct child leaves a grandchild holding the payload.


class WatchdogTripped(RuntimeError):
    """The harness itself failed to reach a terminal state."""


class Decision(enum.Enum):
    FORWARD = "forward"
    REPLACE = "replace"
    REFUSE = "refuse"


class FrameVerdict:
    __slots__ = ("decision", "parsed", "resynchronised", "reason", "message")

    def __init__(self, decision, parsed, resynchronised, reason, message=None):
        self.decision = decision
        self.parsed = parsed
        self.resynchronised = resynchronised
        self.reason = reason
        self.message = message


class Outcome:
    __slots__ = ("request_id", "direction", "forwarded", "replacement",
                 "worker_terminated", "delivered_late", "elapsed_ms",
                 "inspected_utf8_bytes", "inspection_complete", "reason_code")

    def __init__(self, **fields):
        for slot in self.__slots__:
            setattr(self, slot, fields.get(slot))


class Handle:
    """One held message. `result()` is where the watchdog lives."""

    def __init__(self, proxy, request_id, watchdog_ms):
        self._proxy = proxy
        self.request_id = request_id
        self._watchdog_ms = watchdog_ms
        self._done = threading.Event()
        self._outcome: Outcome | None = None

    def _settle(self, outcome: Outcome) -> None:
        self._outcome = outcome
        self._done.set()

    def result(self, timeout: float | None = None) -> Outcome:
        budget = self._watchdog_ms / 1000
        waited = budget if timeout is None else min(timeout, budget)
        if not self._done.wait(waited):
            raise WatchdogTripped(
                f"the harness did not reach a terminal state for request "
                f"{self.request_id!r} within {self._watchdog_ms} ms. This is a "
                f"HARNESS fault and not a scenario result; the run is void.")
        return self._outcome


class Passthrough:
    def __init__(self, deadline_ms: int = 2000, watchdog_ms: int = 3000,
                 wire_frame_limit: int = DEFAULT_WIRE_FRAME_LIMIT,
                 byte_budget: int | None = None):
        self.deadline_ms = deadline_ms
        self.watchdog_ms = watchdog_ms
        self.wire_frame_limit = wire_frame_limit
        self.byte_budget = byte_budget
        self.run_id = uuid.uuid4().hex[:12]
        self.events: list[dict] = []
        self._lock = threading.Lock()
        self._pending: dict = {}
        self._cancelled: set = set()
        self._hold_entered: dict = {}
        self._cancel_accepted: dict = {}
        self._upstream_forwards = 0

    # ── receipts ────────────────────────────────────────────────────────────
    def _emit(self, kind: str, request_id, **fields) -> None:
        with self._lock:
            self.events.append({"run_id": self.run_id, "seq": len(self.events),
                                "at": time.time(), "kind": kind,
                                "request_id": request_id, **fields})

    # ── frames ──────────────────────────────────────────────────────────────
    def read_frame(self, line: str) -> FrameVerdict:
        """Bytes first, parse second, and never a guess about where to resume."""
        raw = line.encode("utf-8", "surrogatepass") if isinstance(line, str) else line
        if len(raw) > self.wire_frame_limit:
            self._emit("FRAME_REFUSED", None, reason="over_wire_frame_limit",
                       bytes=len(raw))
            return FrameVerdict(Decision.REFUSE, parsed=False, resynchronised=False,
                                reason="over_wire_frame_limit")
        if not raw.strip():
            self._emit("FRAME_REFUSED", None, reason="empty_frame", bytes=len(raw))
            return FrameVerdict(Decision.REFUSE, parsed=False, resynchronised=False,
                                reason="empty_frame")
        try:
            message = json.loads(raw)
        except ValueError:
            # No scanning forward for the next byte that looks like a message.
            self._emit("FRAME_REFUSED", None, reason="unparseable", bytes=len(raw))
            return FrameVerdict(Decision.REFUSE, parsed=False, resynchronised=False,
                                reason="unparseable")
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            self._emit("FRAME_REFUSED", None, reason="not_jsonrpc_2")
            return FrameVerdict(Decision.REFUSE, parsed=True, resynchronised=False,
                                reason="not_jsonrpc_2", message=message)
        return FrameVerdict(Decision.FORWARD, parsed=True, resynchronised=False,
                            reason="ok", message=message)

    # ── holding ─────────────────────────────────────────────────────────────
    def submit(self, direction: str, request_id, payload: str, scanner,
               channel: str | None = None) -> Handle:
        """Hold one message, scan it in a killable child, settle. Returns at once."""
        channel = channel or ("message" if direction == "request" else "api_response")
        handle = Handle(self, request_id, self.watchdog_ms)
        with self._lock:
            self._pending[request_id] = handle
            self._hold_entered[request_id] = threading.Event()
            self._cancel_accepted[request_id] = threading.Event()
        self._emit("HOLD_ENTERED", request_id, direction=direction, channel=channel,
                   bytes=len(payload.encode("utf-8", "surrogatepass")))
        self._hold_entered[request_id].set()
        threading.Thread(target=self._run, daemon=True,
                         args=(handle, direction, request_id, payload, scanner,
                               channel)).start()
        return handle

    def _run(self, handle, direction, request_id, payload, scanner, channel) -> None:
        started = time.perf_counter()
        argv = scanner(payload, channel) if callable(scanner) else list(scanner)
        worker = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)
        self._emit("SCAN_STARTED", request_id, pid=worker.pid, argv=argv[:2])
        feeder = threading.Thread(target=_feed, daemon=True, args=(worker, payload))
        feeder.start()
        terminated = False
        try:
            worker.wait(timeout=self.deadline_ms / 1000)
        except subprocess.TimeoutExpired:
            terminated = True
            _kill_group(worker, TERMINATION_GRACE_MS / 1000)
        elapsed_ms = (time.perf_counter() - started) * 1000
        cancelled = request_id in self._cancelled
        if not terminated and cancelled:
            # Cancelled while the scan was still running: the scan is abandoned
            # too, because a worker that finishes after cancellation must not be
            # able to release anything.
            _kill_group(worker, TERMINATION_GRACE_MS / 1000)
        exit_code = worker.poll()
        if cancelled:
            reason = "cancelled_before_release"
        elif terminated:
            reason = "inspection_deadline_exceeded"
        elif exit_code not in (0, None):
            reason = "scanner_failed"
        else:
            reason = None
        forwarded = reason is None
        if forwarded and direction == "request":
            with self._lock:
                self._upstream_forwards += 1
        outcome = Outcome(
            request_id=request_id, direction=direction, forwarded=forwarded,
            worker_terminated=terminated, delivered_late=False,
            elapsed_ms=elapsed_ms, reason_code=reason,
            inspected_utf8_bytes=len(payload.encode("utf-8", "surrogatepass")),
            inspection_complete=forwarded,
            replacement=None if forwarded else self._withheld(
                request_id, reason, elapsed_ms, payload),
        )
        with self._lock:
            self._pending.pop(request_id, None)
        self._emit("SETTLED", request_id, forwarded=forwarded, reason=reason,
                   terminated=terminated, elapsed_ms=round(elapsed_ms, 3))
        handle._settle(outcome)

    def _withheld(self, request_id, reason_code, elapsed_ms, payload) -> dict:
        """A reason code, never the payload and never an exception string."""
        return {
            "jsonrpc": "2.0",
            "id": request_id,                       # type preserved, not normalised
            "error": {
                "code": GATE2_WITHHELD_CODE,
                "message": GATE2_WITHHELD,
                "data": {
                    "reason_code": reason_code or "withheld",
                    "inspection_complete": False,
                    "inspected_utf8_bytes": len(
                        payload.encode("utf-8", "surrogatepass")),
                    "elapsed_ms": round(elapsed_ms, 3),
                },
            },
        }

    # ── cancellation ────────────────────────────────────────────────────────
    def cancel(self, request_id) -> None:
        with self._lock:
            self._cancelled.add(request_id)
        self._emit("CANCEL_ACCEPTED", request_id)
        self._cancel_accepted[request_id].set()

    def await_hold_entered(self, request_id, timeout: float = 1.0) -> bool:
        event = self._hold_entered.get(request_id)
        return bool(event and event.wait(timeout))

    def await_cancel_accepted(self, request_id, timeout: float = 1.0) -> bool:
        event = self._cancel_accepted.get(request_id)
        return bool(event and event.wait(timeout))

    def pending_ids(self) -> set:
        with self._lock:
            return set(self._pending)

    def upstream_forwards(self) -> int:
        with self._lock:
            return self._upstream_forwards


def _feed(worker, payload: str) -> None:
    """The worker reads the document on stdin, as the scenario package defines."""
    try:
        worker.stdin.write(payload.encode("utf-8", "surrogatepass"))
        worker.stdin.close()
    except (BrokenPipeError, ValueError, OSError):
        pass          # a worker that died before reading is the caller's answer


def _kill_group(worker, grace: float) -> None:
    """TERM the whole process group, then KILL. A grace period may not release
    payloads: it exists so a dying worker can close its files, nothing else."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if worker.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(worker.pid), sig)
        except (ProcessLookupError, PermissionError):
            return
        try:
            worker.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            continue
