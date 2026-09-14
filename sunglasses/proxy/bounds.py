"""T8's bounds, and what each breach is called.

Written against `tests/test_proxy_bounds.py`, committed first from the rows.

A bound is three decisions and only the first is the number. The value, whether
it is INCLUSIVE, and what the breach is CALLED. The second is where off-by-ones
live: an exclusive reading of an inclusive cap hands an attacker exactly one free
byte at every boundary and fails two shipped fixtures that sit precisely on it.
The third is where ungradeable receipts live: a breach reported under the wrong
reason cannot be compared to the expectation that describes it.

The reasons here are T4.R5's frozen catalog, and `budget` is populated ONLY for
OVER_BUDGET, per T4.R7 v5.1. A deadline is not a budget breach, and saying
`budget: content` on a SCAN_DEADLINE would describe a bound that did not break.
"""
from __future__ import annotations

# ── the frozen values ──────────────────────────────────────────────────────
WIRE_FRAME_BYTES = 4_194_304          # R1, incl. LF
CONTENT_BYTES = 262_144               # R2, inclusive
FRAME_ASSEMBLY_MS = 2_000             # R3
INSPECTION_MS = 2_000                 # R4
KILL_GRACE_MS = 250                   # R4
UPSTREAM_RESPONSE_MS = 60_000         # R5
OUTSTANDING = 8                       # R6
QUEUED_BYTES = 16 * 1024 * 1024       # R6
WORKER_STDOUT_BYTES = 1024 * 1024     # R7
STDERR_PER_MESSAGE = 256 * 1024       # R8
STDERR_PER_MINUTE = 1024 * 1024       # R8
WRITE_STALL_MS = 5_000                # R9
WATCHDOG_SLACK_MS = 3_000             # R10
MAX_DEPTH = 64                        # R11
MAX_NODES = 100_000                   # R11
SNAPSHOT_PAGES = 64                   # R13
SNAPSHOT_TOOLS = 512                  # R13
SNAPSHOT_BYTES = 4 * 1024 * 1024      # R13
SNAPSHOT_DEADLINE_MS = 10_000         # R13

# Each deadline is named and separate. One shared constant would make four
# different promises the same number, and 2,000 ms to assemble a frame is not
# the same undertaking as 60,000 ms for a server to answer.
DEADLINES = {
    "frame_assembly": FRAME_ASSEMBLY_MS,
    "inspection": INSPECTION_MS,
    "upstream_response": UPSTREAM_RESPONSE_MS,
    "write_stall": WRITE_STALL_MS,
}


class Breach:
    """What broke, what it is called, and which bound it was.

    Falsy when nothing broke, so a caller reads `if breach:` rather than
    comparing to None and getting it wrong in the direction that continues.
    """

    __slots__ = ("reason", "rule", "budget", "detail", "inspection_complete")

    def __init__(self, reason=None, rule=None, budget=None, detail=None,
                 inspection_complete=None):
        self.reason = reason
        self.rule = rule
        self.budget = budget
        self.detail = detail
        self.inspection_complete = inspection_complete

    def __bool__(self):
        return self.reason is not None

    def as_receipt(self):
        return {"reason_code": self.reason, "rule": self.rule,
                "budget": self.budget}

    def __repr__(self):
        return f"<Breach {self.reason or 'none'}{'/' + self.budget if self.budget else ''}>"


_OK = Breach()


def check_frame(size):
    """R1. Inclusive: the cap counts the LF and a frame AT it is allowed."""
    if size <= WIRE_FRAME_BYTES:
        return _OK
    return Breach("OVER_BUDGET", "S3", budget="frame",
                  detail=f"{size} bytes over the {WIRE_FRAME_BYTES} frame cap")


def check_content(size):
    """R2. Inclusive, and two shipped fixtures sit exactly on it."""
    if size <= CONTENT_BYTES:
        return _OK
    return Breach("OVER_BUDGET", "S3", budget="content", inspection_complete=False,
                  detail=f"{size} decoded bytes over the {CONTENT_BYTES} cap")


def check_admission(*, outstanding, queued):
    """R6. BOTH limits, because checking one leaves the other reachable.

    `outstanding` is compared with `>=` because the number is a count of items
    already held: admitting one more at the limit would make it nine.
    """
    if outstanding >= OUTSTANDING:
        return Breach("OVERLOADED", "S3",
                      detail=f"{outstanding} correlations already outstanding")
    if queued > QUEUED_BYTES:
        return Breach("OVERLOADED", "S3",
                      detail=f"{queued} bytes queued over the {QUEUED_BYTES} cap")
    return _OK


def overload_victim():
    """T6.R7 and R6. The NEW item is refused; a held one is never dropped.

    Dropping a held message to make room withdraws an answer somebody is already
    waiting for, which turns a load problem into a correctness one.
    """
    return "new"


def check_deadline(name, *, elapsed_ms):
    """R3, R4, R5, R9. Expired AFTER the limit, never at it.

    `budget` stays None. A deadline is not a budget breach, and naming one would
    describe a bound that did not break.

    An unknown name raises rather than defaulting, because a typo that silently
    picks some other row's number gives a bound nobody chose.
    """
    limit = DEADLINES[name]
    if elapsed_ms <= limit:
        return _OK
    return Breach("SCAN_DEADLINE", "S3",
                  detail=f"{name} took {elapsed_ms} ms against a {limit} ms limit")


def watchdog_deadline_ms(name):
    """R10. Strictly PAST the deadline it guards.

    The watchdog exists to catch a deadline that did not fire, so it cannot
    share a boundary with one: at equal values the thing being watched and the
    watcher race, and the receipt then depends on which won.
    """
    return DEADLINES[name] + WATCHDOG_SLACK_MS


def check_snapshot(*, pages, tools, decoded, elapsed_ms, cursors=()):
    """R13. Four totals and a cursor rule, each its own answer.

    A repeated cursor is a FAULT rather than a stopping condition. A server
    returning the same cursor for ever would otherwise page until some other
    limit caught it, and stopping quietly at that point would activate a PREFIX
    of the descriptor set, which the row forbids in its closing words.
    """
    if pages > SNAPSHOT_PAGES:
        return Breach("APPROVAL_REQUIRED", "S4",
                      detail=f"{pages} pages over the {SNAPSHOT_PAGES} cap")
    if tools > SNAPSHOT_TOOLS:
        return Breach("APPROVAL_REQUIRED", "S4",
                      detail=f"{tools} tools over the {SNAPSHOT_TOOLS} cap")
    if decoded > SNAPSHOT_BYTES:
        return Breach("APPROVAL_REQUIRED", "S4",
                      detail=f"{decoded} decoded bytes over the snapshot cap")
    if elapsed_ms > SNAPSHOT_DEADLINE_MS:
        return Breach("APPROVAL_REQUIRED", "S4",
                      detail=f"the list took {elapsed_ms} ms")
    seen = set()
    for cursor in cursors or ():
        if cursor in seen:
            return Breach("APPROVAL_REQUIRED", "S4",
                          detail=f"the cursor {cursor!r} repeated, so the list "
                                 f"does not terminate")
        seen.add(cursor)
    return _OK


def may_activate_partial_snapshot():
    """R13's closing words, as a function so the answer is stated once.

    A prefix of a descriptor set is not a smaller version of it. The tools that
    did not arrive are exactly the ones an approval would not have covered, so
    activating on what did arrive approves a set nobody reviewed.
    """
    return False


def exit_status(*, fatal, upstream_code, pending):
    """R14. Nonzero on a fault, the upstream's own code otherwise.

    The clean code is PROPAGATED rather than flattened to zero, which is the
    row's word: a server that exited 7 said something, and reporting 0 throws
    away its answer about how it ended.
    """
    if fatal:
        return 1
    if pending:
        return 1                      # T7.R1, exit with pending calls is S5
    return upstream_code
