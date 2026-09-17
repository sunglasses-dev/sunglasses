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

import hashlib
import threading
import uuid
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


def _snapshot(value):
    """A deep copy for the shapes a detail is allowed to be."""
    if isinstance(value, dict):
        return {k: _snapshot(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_snapshot(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_snapshot(v) for v in value)
    return value


def _item_digest(request_id):
    """A stable, non-reversing handle for an id of any JSON type."""
    if request_id is None:
        return None
    raw = f"{type(request_id).__name__}:{request_id!r}".encode(
        "utf-8", "surrogatepass")
    return hashlib.sha256(raw).hexdigest()[:16]


class Settled(Exception):
    """An attempt to settle an item that already has an answer."""


class Cause:
    __slots__ = ("reason", "rule", "budget", "at", "detail", "_frozen")

    def __init__(self, reason, rule, budget=None, detail=None):
        object.__setattr__(self, "_frozen", False)
        self.reason = reason
        self.rule = rule
        self.budget = budget
        self.detail = detail
        self.at = time.monotonic()

    def __setattr__(self, name, value):
        """Frozen means frozen, not "please do not touch".

        A copy stops the CALLER's reference from mattering. It does not stop the
        copy itself from being changed by anyone who is handed it, and this
        object is handed out by `settle`, `settled_as`, `causes`,
        `terminal_cause` and both teardown paths. Review reached it through four
        of those. So the stored record refuses writes rather than relying on
        every future caller being polite.
        """
        if getattr(self, "_frozen", False):
            raise AttributeError(
                f"this cause is a settled record and cannot be changed; "
                f"{name} stays {getattr(self, name, None)!r}")
        object.__setattr__(self, name, value)

    def __delattr__(self, name):
        """Deleting is changing, and `__setattr__` does not cover it.

        The guard above refused writes and left `del cause.rule` open, so a
        holder of a returned record could remove the field rather than alter it
        and the stored record lost it too. An attribute that is GONE is worse
        than one that is wrong: the receipt no longer says anything about the
        rule, and code that reads it raises rather than disagreeing.

        Found by review as V05, on values returned by `record()` and `settle()`.
        The lesson is that "immutable" is a property of every mutating verb, and
        I had only thought of one of them.
        """
        if getattr(self, "_frozen", False):
            raise AttributeError(
                f"this cause is a settled record and cannot be changed; "
                f"{name} cannot be deleted")
        object.__delattr__(self, name)

    def frozen(self):
        """A copy, because the caller keeps a reference to the original.

        `settle` used to store the caller's object. Mutating it afterwards
        changed what `settled_as` reported, so a settled record was only as
        immutable as the politeness of whoever held the other reference.
        """
        # SNAPSHOT the detail. It may be a mutable structure the caller still
        # holds, and a frozen record whose contents change underneath it is not
        # frozen in any sense that matters. V01 mutates a nested list to prove
        # it, and a shallow copy of the Cause is not enough.
        copy = Cause(self.reason, self.rule, self.budget,
                     _snapshot(self.detail))
        copy.at = self.at
        object.__setattr__(copy, "_frozen", True)
        return copy

    def as_receipt(self):
        """An ALLOWLIST, for the same reason `Frame.as_receipt` is one.

        `detail` is prose, it is built around whatever the situation contained,
        and a session cause carries it into every event. The frame receipt leaked
        peer material through exactly this field twice. Reason, rule and budget
        come from fixed vocabularies; detail does not, so it stays on the object
        for logs and exceptions and never enters evidence.
        """
        return {"reason_code": self.reason, "rule": self.rule,
                "budget": self.budget}

    def __repr__(self):
        return f"<Cause {self.rule}/{self.reason}>"


# T4.R4. Rule A makes a FAULT terminal. Rule B keeps a NORMAL COMPLETION
# provisional until settlement, so a later hold or protocol fault still wins.
# S1 allow, S2 prohibition and S7 review are completions; S3 faults and the
# S4/S6 holds are not.
# GENUINE FAULTS ONLY. S4 and S6 were in here, which made an approval hold
# irrevocable and let it outrank a later accepted cancellation. A hold is not a
# fault: it is a decision not to proceed yet, it is Rule B, and T4.R4's numbered
# order puts cancellation (3) above approval (4). Rule A is for the things that
# went WRONG, which is S3 and S5.
_FAULT_RULES = frozenset({"S3", "S5"})
_HOLD_RULES = frozenset({"S4", "S6"})

# T4.R4's order, for holds known at one settlement instant.
_HOLD_ORDER = {"S6": 3, "S4": 4}

# WHERE A SETTLEMENT CAME FROM. T9's ruling of 2026-09-13, to be confirmed or
# overruled by ASTRA with a row id.
#
# The contract's S5 trigger for an unsolicited response is a WIRE event: a
# response FRAME arriving from upstream for an id nobody issued. A caller
# handing this object an id it does not own is a different thing entirely, and
# the API must not conflate them. So the origin is stated rather than guessed:
# an unowned id from the WIRE closes the session, an unowned id from a CALLER is
# refused and changes nothing.
#
# Without this parameter the two cases are indistinguishable at the API, which
# is why ASTRA's C03 and his Q14 could both be reasonable and still contradict
# each other.
ORIGIN_API = "api"
ORIGIN_UPSTREAM = "upstream"
ORIGIN_CLIENT = "client"


def is_fault(cause):
    return cause.rule in _FAULT_RULES


def is_hold(cause):
    return cause.rule in _HOLD_RULES


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
        # The salt that makes an item token opaque between sessions. Random per
        # session rather than derived from anything, so two receipts cannot be
        # joined on it even by someone who knows how it is built.
        self.run_id = uuid.uuid4().hex
        self._torn_down = None
        self._tearing_down = False
        self._closed = False
        self._pending_supervisor = None
        self._answers: dict = {}
        self.events: list = []

    # ── what the client is owed ─────────────────────────────────────────────
    def admit(self, request_id, *, method=None, origin=ORIGIN_CLIENT):
        """Record a request forwarded upstream and not yet answered.

        `method` is the method the request was issued with, kept so a later
        response can be checked against the request it claims to answer. The
        record used to be a bare timestamp, which is why T2 and T13 of ASTRA's
        round 2 could not be satisfied: nothing here knew what a pending id was
        waiting for. Nothing reads it yet; the pump does.

        Three refusals, and two of them were missing. The old version replaced
        an existing entry and returned success, so a second call with a live id
        silently retired the first request; and it accepted an id that had
        already been settled, so a cancelled id could be reused and answered
        twice. ASTRA's G2-20 derivatives execute both.

        A DUPLICATE PENDING ID TEARS THE SESSION DOWN. It is not a busy signal:
        the peer and we disagree about which request an id names, so every
        correlation after it is a guess. That is a protocol fault, T7.R1, and
        the session cannot continue through it.
        """
        with self._lock:
            if not self._admitting:
                return False
            if request_id in self._settled:
                self._emit("ADMISSION_REFUSED", request_id, reason="retired_id")
                return False
            if request_id in self._owed:
                self._emit("ADMISSION_REFUSED", request_id,
                           reason="duplicate_pending_id")
                self._teardown_locked(Cause(
                    "MALFORMED_CLIENT", "S5",
                    detail="a second request arrived carrying an id already "
                           "pending, so correlation is no longer sound"))
                return False
            self._owed[request_id] = {"at": time.monotonic(),
                                      "method": method, "origin": origin}
            return True

    def owed(self):
        with self._lock:
            return list(self._owed)

    def expected_method(self, request_id):
        """What a pending id is waiting for, or None if it is not pending."""
        with self._lock:
            record = self._owed.get(request_id)
            return record["method"] if record else None

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
            stored = cause.frozen()
            self._causes.setdefault(request_id, []).append(stored)
            self._emit("CAUSE_RECORDED", request_id, **stored.as_receipt())
            # A SEPARATE COPY GOES OUT. Returning the stored object hands the
            # caller a reference to the record itself. `frozen()` stops the
            # attributes being reassigned and leaves a mutable detail reachable
            # through them, so `exposed.detail["indices"].append(2)` edited the
            # stored cause. Freezing the shell is not freezing the contents.
            return stored.frozen()

    def causes(self, request_id):
        with self._lock:
            return [cause.frozen() for cause in self._causes.get(request_id, [])]

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
            for cause in recorded:
                if is_fault(cause):
                    return cause              # Rule A, the FIRST one
            holds = [c for c in recorded if is_hold(c)]
            if holds:
                # Rule B. No fault, so the strongest HOLD decides, by T4.R4's
                # order rather than by arrival: a cancellation outranks an
                # approval hold whichever was recorded first.
                return min(holds, key=lambda c: (_HOLD_ORDER.get(c.rule, 9),
                                                 c.at))
            return None

    @staticmethod
    def precedence_winner(causes):
        """T4.R4's numbered order, for causes known at ONE settlement instant."""
        if not causes:
            return None
        return min(causes, key=lambda c: (_PRECEDENCE.get(c.reason, 99), c.at))

    # ── settlement ──────────────────────────────────────────────────────────
    def settle(self, request_id, cause, *, origin=ORIGIN_API):
        """Answer an item once, with the cause that is actually terminal.

        Four refusals and one substitution, three of which were missing.

        UNKNOWN IDS. The old version checked only whether an id was already
        settled, so any id at all could be settled, including one the client
        never issued. G2-20's unsolicited response and G2-15's reverse request,
        which deliberately reuses a pending client id, both land here. Settling
        an id we do not owe an answer for either invents a response or retires
        somebody else's request, so an unknown id is refused and REPORTED rather
        than raising, since it is a fact about the peer and not a bug in us.

        AFTER TEARDOWN. Nothing new is settled once the session has ended.

        TWICE. Still raises, because a caller that settles an item it already
        settled has a bug in its own ordering and a silent overwrite puts two
        answers for one id on the wire.

        AND THE CAUSE MAY NOT BE THE ONE OFFERED. T4.R4 Rule A: if a FAULT was
        recorded for this item first, that fault is terminal and the caller's
        cause does not replace it. A recorded deadline followed by a clean
        settlement used to become clean.
        """
        with self._lock:
            if request_id in self._settled:
                raise Settled(
                    f"{request_id!r} was already settled as "
                    f"{self._settled[request_id].reason}; refusing to answer it "
                    f"again with {cause.reason}")
            if request_id not in self._owed:
                self._emit("SETTLEMENT_REFUSED", request_id,
                           reason="not_owed", offered=cause.reason,
                           origin=origin)
                if origin == ORIGIN_UPSTREAM:
                    # A response FRAME for an id nobody issued. T7.R1 names that
                    # an S5 trigger, and it is a fact about the peer rather than
                    # about the caller, so the session cannot continue.
                    self._teardown_locked(Cause(
                        "MALFORMED_UPSTREAM", "S5",
                        detail="a response arrived from upstream for an id "
                               "that was never issued"))
                return None
            if self._torn_down is not None and not self._tearing_down:
                self._emit("SETTLEMENT_REFUSED", request_id,
                           reason="session_closed", offered=cause.reason)
                return None
            return self._settle_locked(request_id, cause)

    def _settle_locked(self, request_id, cause):
        recorded = self.terminal_cause(request_id)
        terminal = (recorded or cause).frozen()
        self._settled[request_id] = terminal
        self._owed.pop(request_id, None)
        self._emit("SETTLED", request_id, **terminal.as_receipt())
        return terminal

    def settle_or_report(self, request_id, cause, *, origin=ORIGIN_API):
        """Settle it, or say it was ALREADY settled. One lock, one answer.

        R-179-R6/R5_WITHHOLD_CLOSE. Callers asked `settled_as` and then called
        `settle`, which is check-then-act across two acquisitions of this lock:
        a legitimate teardown landing between them settles the token, and the
        `settle` that follows raises `Settled` out of `Route.client_frame` --
        an exception reaching a client where a receipt belongs. ADJACENT LINES
        ARE NOT ATOMICITY; the pair has to be one critical section, and this is
        it.

        Returns `(terminal, already)`. `already` is True when something else
        answered it first, and the terminal cause returned is THAT answer, so
        the caller reports rather than guesses. Nothing here raises `Settled`:
        a caller that wants the exception still has `settle`.
        """
        with self._lock:
            settled = self._settled.get(request_id)
            if settled is not None:
                return settled, True
            if request_id not in self._owed:
                self._emit("SETTLEMENT_REFUSED", request_id,
                           reason="not_owed", offered=cause.reason,
                           origin=origin)
                return None, False
            if self._torn_down is not None and not self._tearing_down:
                self._emit("SETTLEMENT_REFUSED", request_id,
                           reason="session_closed", offered=cause.reason)
                return None, False
            return self._settle_locked(request_id, cause), False

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
            return self._teardown_locked(cause, stop_processes=stop_processes)

    def _teardown_locked(self, cause, *, stop_processes=None):
        """The lock is already held. `admit` tears down from inside it.

        A REPEAT TEARDOWN RETURNS THE SAME ANSWERS rather than an empty dict.
        The old version returned `{}`, and combined with stopping the processes
        before returning, an injected supervisor that raised left the only copy
        of the batch unreachable: the items were settled, the caller never saw
        them, and the retry reported nothing to deliver. Settling is what must
        happen once; DELIVERING the answers can safely happen again, and losing
        them cannot.
        """
        if self._torn_down is not None:
            self._emit("TEARDOWN_REPEATED", None, reason=cause.reason,
                       redelivering=len(self._answers))
            # Settling already happened. Closing may not have, if the supervisor
            # raised last time, so the retry goes through the same close path.
            return self._close_locked(stop_processes)
        self._admitting = False
        self._torn_down = cause
        self._emit("TEARDOWN", None, **cause.as_receipt())

        self._tearing_down = True
        try:
            for request_id in list(self._owed):
                # The first FAULT recorded for that item, and the teardown cause
                # otherwise. An item that already failed for its own reason
                # keeps it; a NORMAL completion is provisional per Rule B and
                # does not survive a protocol fault that ends the session.
                self._answers[request_id] = self._settle_locked(request_id, cause)
        finally:
            self._tearing_down = False

        return self._close_locked(stop_processes)

    def _close_locked(self, stop_processes):
        """Supervise, THEN say it closed, THEN hand back the batch.

        The order is the whole point and I had it inside out twice. First the
        supervisor ran after the answers were returned, so a raising supervisor
        took the only copy of the batch with it. Then I moved the return earlier
        and emitted UPSTREAM_CLOSED before supervising, which fixed the loss and
        introduced a worse claim: a receipt saying the upstream had closed while
        the child was still running.

        A retry re-supervises. It does not redeliver on the strength of a
        previous attempt that failed, because the batch is only safe to hand
        back once something has actually stopped the processes holding it.
        """
        # THE SUPERVISOR THAT FAILED IS REMEMBERED. A retry that arrives with no
        # callback used to skip supervision entirely, set `_closed`, emit the
        # closure and hand back the batch with the child still alive. The
        # default argument is not a statement that nothing needs stopping; it is
        # a caller who did not say. So the last supervisor that did not complete
        # is retained and reused, and a close cannot be claimed while one is
        # outstanding and unsupplied.
        supervisor = stop_processes if stop_processes is not None else self._pending_supervisor
        if supervisor is not None and not self._closed:
            self._pending_supervisor = supervisor
            stopped = supervisor()      # raises out of teardown, nothing claimed
            if stopped is False:
                # A SUPERVISOR THAT SAYS FALSE HAS NOT STOPPED ANYTHING, and
                # `stop_group` returns exactly that when it could not signal a
                # group. Treating a returned value as success because no
                # exception was raised is the same error as reading an exit code
                # instead of a result, which this package has now made twice.
                # Nothing is claimed and nothing is handed back.
                self._emit("SUPERVISOR_INCOMPLETE", None)
                return {}
            self._pending_supervisor = None
        if self._closed:
            # V03. Closure is announced once. A retry after a successful close
            # redelivers the batch; it does not re-announce an event that
            # already happened.
            return dict(self._answers)
        self._closed = True
        if supervisor is not None:
            # UPSTREAM_CLOSED IS A CLAIM ABOUT PROCESSES, so it is only made
            # when something actually supervised them. A teardown with no
            # supervisor has settled every item and stopped nothing, which is a
            # true and different statement, and saying the upstream closed there
            # puts a false sentence in the evidence while a child is still
            # running.
            self._emit("UPSTREAM_CLOSED", None, settled=len(self._answers))
        else:
            self._emit("SESSION_TORN_DOWN", None, settled=len(self._answers),
                       supervised=False)
        return dict(self._answers)

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
        """Receipts identify an item, they do not reproduce it.

        A JSON-RPC id is peer-supplied text of arbitrary length and content, and
        these events are evidence. The digest correlates every event about one
        item without copying the id into the record, and the type is kept
        because 4 and "4" are different ids and the contract requires the
        distinction to survive.
        """
        self.events.append({
            "seq": len(self.events),
            "mono": time.monotonic(),
            # T9's schema. `mono_ns` because two events inside one millisecond
            # are ordinary and a duration between them should not round to
            # zero; `wall` beside it because that is what a human correlates
            # against everything else.
            "mono_ns": time.monotonic_ns(),
            "wall": time.time(),
            "kind": kind,
            "item": self._item_token(request_id),
            "id_token": self._item_token(request_id),
            "id_type": type(request_id).__name__,
            "item_type": type(request_id).__name__,
            **fields})

    def _item_token(self, request_id):
        """Opaque, and opaque ACROSS SESSIONS as well as within one.

        A bare digest of the id is stable everywhere, so the same id yields the
        same token in every run and anyone holding two receipts can join them
        and recover which requests were the same. Salting with the run id keeps
        the token correlatable inside a session, which is what a reader needs,
        and useless between them, which is what a peer-supplied id deserves.
        """
        if request_id is None:
            return None
        raw = f"{self.run_id}:{type(request_id).__name__}:{request_id!r}"
        return hashlib.sha256(
            raw.encode("utf-8", "surrogatepass")).hexdigest()[:16]
