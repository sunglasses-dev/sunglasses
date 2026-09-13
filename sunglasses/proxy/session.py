"""Settling every held request exactly once, with the cause that came first.

T7.R2 is a teardown procedure, and the part of it that is easy to get wrong is
not killing processes. It is this sentence: "settle each KNOWN pending client
request ONCE with the FIRST recorded cause and rule". Three separate claims hide
in it and each one has a way of failing quietly.

  ONCE. A request settled twice sends the client two answers for one id. The
  second is not merely redundant: it can carry a different reason from the
  first, and whichever the client keeps is then decided by arrival order.

  KNOWN. The requests a client is owed an answer for are not the ones being
  scanned right now. By the time a teardown runs, the scans may all have
  finished and left; what remains owed is everything forwarded and not yet
  answered.

  THE FIRST CAUSE. A fault does not become a different fault because a later one
  arrives. T4.R4 Rule A is explicit that a recorded fault is terminal and is
  never superseded by a later cancellation, and Rule B carves out the one
  exception in the other direction, a NORMAL completion that has not yet
  settled.

So this module owns the causes, not the killing. Process teardown is injected,
which also means the ordering rules can be tested without spawning anything.
"""
from __future__ import annotations

import threading
import time

from . import framing

# T4.R4's precedence, as an explicit order. Lower sorts first. This exists so
# "which cause wins" is a table rather than a chain of ifs that reads correctly
# and evaluates in the wrong order.
_PRECEDENCE = {
    framing.MALFORMED_UPSTREAM: 1,
    framing.MALFORMED_CLIENT: 1,
    framing.OVER_BUDGET: 2,
    "OVERLOADED": 2,
    "REQUEST_CANCELLED": 3,
    "APPROVAL_REQUIRED": 4,
    "DESCRIPTOR_CHANGED": 4,
    "UNSUPPORTED_CONTENT": 5,
    "UNINSPECTED_METHOD": 5,
    "SCAN_EXCEPTION": 6,
    "SCAN_DEADLINE": 6,
    "PROHIBITED_SECRET": 7,
    "PROHIBITED_CONTENT": 7,
    "REVIEW_REQUIRED": 8,
    "CLEAN": 9,
}


class Settled(Exception):
    """An attempt to settle an item that already has an answer."""


class Cause:
    __slots__ = ("reason", "rule", "budget", "at", "detail")

    def __init__(self, reason, rule, budget=None, detail=None):
        self.reason = reason
        self.rule = rule
        self.budget = budget
        self.detail = detail
        self.at = time.monotonic()

    def as_receipt(self):
        return {"reason_code": self.reason, "rule": self.rule,
                "budget": self.budget, "detail": self.detail}

    def __repr__(self):
        return f"<Cause {self.rule}/{self.reason}>"


class Session:
    """What is owed, what went wrong, and what has already been answered."""

    def __init__(self):
        # ONE lock for the whole state, per T7.R2. Separate locks for "pending"
        # and "settled" is how an item gets answered twice: the check and the
        # settle have to be one atomic step or two threads both pass the check.
        self._lock = threading.RLock()
        self._owed: dict = {}          # id -> when it was forwarded
        self._causes: dict = {}        # id -> [Cause], first recorded first
        self._settled: dict = {}       # id -> Cause it was settled with
        self._admitting = True
        self._torn_down = None
        self.events: list = []

    # ── what the client is owed ─────────────────────────────────────────────
    def admit(self, request_id):
        """Record a request forwarded upstream and not yet answered.

        Refused once teardown has begun, because admitting after the decision to
        stop is how a request arrives that nothing will ever answer.
        """
        with self._lock:
            if not self._admitting:
                return False
            self._owed[request_id] = time.monotonic()
            return True

    def owed(self):
        with self._lock:
            return list(self._owed)

    def is_settled(self, request_id):
        with self._lock:
            return request_id in self._settled

    # ── causes ──────────────────────────────────────────────────────────────
    def record(self, request_id, cause):
        """Remember a cause. Recording is not settling.

        Every cause is kept, in order, because the receipt has to be able to
        show that a later one arrived and did not win. Dropping it would make
        the record agree with the rule by having no evidence against it.
        """
        with self._lock:
            self._causes.setdefault(request_id, []).append(cause)
            self._emit("CAUSE_RECORDED", request_id, **cause.as_receipt())
            return cause

    def causes(self, request_id):
        with self._lock:
            return list(self._causes.get(request_id, []))

    def terminal_cause(self, request_id):
        """T4.R4 Rule A: the FIRST recorded fault, not the most recent one.

        `min` by recorded order rather than by precedence, because precedence
        decides between causes known at the SAME settlement instant and this
        decides between causes recorded at different times. Sorting by
        precedence here would let a later, higher-precedence fault rewrite an
        earlier one, which is exactly what Rule A forbids.
        """
        with self._lock:
            recorded = self._causes.get(request_id) or []
            return recorded[0] if recorded else None

    @staticmethod
    def precedence_winner(causes):
        """T4.R4's numbered order, for causes known at ONE settlement instant."""
        if not causes:
            return None
        return min(causes, key=lambda c: (_PRECEDENCE.get(c.reason, 99), c.at))

    # ── settlement ──────────────────────────────────────────────────────────
    def settle(self, request_id, cause):
        """Answer an item once. A second attempt raises rather than overwriting.

        Raising rather than returning False because a caller that settles twice
        has a bug in its own ordering, and a silent second settle is two answers
        on the wire for one id with the client choosing by arrival order.
        """
        with self._lock:
            if request_id in self._settled:
                raise Settled(
                    f"{request_id!r} was already settled as "
                    f"{self._settled[request_id].reason}; refusing to answer it "
                    f"again with {cause.reason}")
            self._settled[request_id] = cause
            self._owed.pop(request_id, None)
            self._emit("SETTLED", request_id, **cause.as_receipt())
            return cause

    def settled_as(self, request_id):
        with self._lock:
            return self._settled.get(request_id)

    # ── teardown ────────────────────────────────────────────────────────────
    def teardown(self, cause, *, stop_processes=None):
        """T7.R2. Stop admitting, settle everything owed, once, first cause wins.

        Returns the causes each owed item was settled with, so the caller can
        write one client error per item. Idempotent: a second teardown settles
        nothing, because everything is already answered and re-answering is the
        defect this exists to prevent.
        """
        with self._lock:
            if self._torn_down is not None:
                self._emit("TEARDOWN_REPEATED", None, reason=cause.reason)
                return {}
            self._admitting = False
            self._torn_down = cause
            self._emit("TEARDOWN", None, **cause.as_receipt())

            answers = {}
            for request_id in list(self._owed):
                # The first cause recorded FOR THAT ITEM, and only the teardown
                # cause when the item has none of its own. An item that already
                # failed for its own reason does not get relabelled with the
                # reason the session ended.
                answers[request_id] = self.settle(
                    request_id, self.terminal_cause(request_id) or cause)
            if stop_processes is not None:
                stop_processes()
            self._emit("UPSTREAM_CLOSED", None, settled=len(answers))
            return answers

    @property
    def torn_down(self):
        with self._lock:
            return self._torn_down is not None

    def admitting(self):
        with self._lock:
            return self._admitting

    def exit_code(self):
        """T7.R2 ends nonzero. A session that tore down did not succeed, and a
        zero exit is read by everything upstream of us as "it worked"."""
        return 1 if self.torn_down else 0

    def _emit(self, kind, request_id, **fields):
        self.events.append({"seq": len(self.events), "mono": time.monotonic(),
                            "kind": kind, "request_id": request_id, **fields})
