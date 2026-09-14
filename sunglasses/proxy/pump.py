"""Correlating what arrives with what was asked, and refusing when it does not.

Written against `tests/test_proxy_pump.py`, which was committed first and drawn
from the contract rows rather than from this file. Where the two disagree the
rows win.

T6.R6 is the row that shapes everything here: an id is stored as (origin, JSON
type, value), not as a value. Almost every correlation defect in this component's
history is the same mistake in different clothing. A pump that keys by value
alone answers a string id with a number's result and the client cannot tell,
because what comes back looks like its own id. A pump that ignores origin lets
an upstream request that happens to reuse a client's id retire the client's
request, which is G2-15.

The other shaping rule is T7.R2's last sentence: never resynchronise. A stream
that has produced one frame we cannot trust does not become trustworthy again at
the next newline, so reading stops rather than resumes.
"""
from __future__ import annotations

import threading

from . import framing, handshake, supervisor
from .session import Cause, Session as CoreSession

ORIGIN_CLIENT = "client"
ORIGIN_UPSTREAM = "upstream"
# T6.R6. The proxy's own control traffic. T2.R6 turns one client tools/list
# into up to sixty four proxy requests under T8.R13, and the client's single id
# can answer exactly one of them, so the proxy owns ids of its own or it cannot
# page a tool list at all.
ORIGIN_PROXY = "proxy"

# The prefix is OURS. An id shaped like this arriving from the CLIENT is
# MALFORMED_CLIENT, never control traffic: otherwise the prefix is an
# authentication claim anyone on the other end of the pipe can make, and a
# client holding a control id could settle the proxy's own pending request.
CONTROL_PREFIX = "sg-"

# T6.R6. Bounded, because a tombstone table that grows with the session is a
# memory bound a peer controls.
TOMBSTONE_LIMIT = 10_000


def parsed_ok_but_unterminated(raw):
    """True for a frame that is within the wire bound and has no terminator.

    The size test comes first because an over-long frame arrives as a bounded
    PREFIX that also has no terminator, and that one is OVER_BUDGET rather than
    malformed: reporting it as a missing terminator would name the wrong bound
    and could not be graded against the fixture that describes it.
    """
    return len(raw) <= framing.MAX_FRAME_BYTES and not raw.endswith(b"\n")


def _is_control_id(request_id):
    """Exactly the shape, not a resemblance: a string carrying our prefix."""
    return isinstance(request_id, str) and request_id.startswith(CONTROL_PREFIX)


def key(origin, request_id):
    """T6.R6's identity: origin, JSON type, value.

    The type is in the key rather than compared afterwards, because `"2001"` and
    `2001` are equal to a human reading a receipt and must never be equal to
    this. Python would keep them distinct in a dict on its own; naming the type
    makes the rule legible and survives anyone who later "simplifies" the key to
    the value.
    """
    return (origin, type(request_id).__name__, request_id)


class UnsupervisedUpstream(RuntimeError):
    """Strict mode was asked to read from a pipe with no process behind it."""


class Session:
    """The correlation table, the tombstones, and the decision to stop reading."""

    def __init__(self, upstream=None, *, pgid=None, strict=False):
        self._upstream = upstream
        self._pgid = pgid
        self._strict = strict
        self._watcher = None
        self._core = CoreSession()
        self._pending: dict = {}          # key -> method
        self._answered: set = set()
        # ONE TABLE for correlation, keyed by origin, and one hand-off dict
        # beside it for answers the client must never see. Not a second
        # correlation table: two of those drift, and the one that drifts is
        # the one holding the tombstones, so a cancelled id becomes reusable
        # in whichever namespace nobody was watching.
        self._control_answers: dict = {}
        self._tombstones: list = []       # keys, oldest first
        # T6.R1. Who is still owed one answer, retained across the close that
        # discovered the fault so the reader can deliver it on the way out.
        self._owed_refusals: list = []
        # One settlement owner. The reader and the watcher both reach the debt
        # and only one of them may be holding it at a time.
        self._settlement = threading.Lock()
        self._generation: dict = {}       # key -> how many times it has been issued
        self._closed: tuple | None = None

    # ── admission ───────────────────────────────────────────────────────────
    def admit_request(self, request_id, *, method, origin):
        """T6.R6. A duplicate typed id from the client closes the session."""
        if self._closed:
            return False
        # T2.R16. An extension or unknown method from the client is refused AT
        # ADMISSION, so upstream never sees it. Refusing it later, after it has
        # been forwarded, is a different and much weaker promise.
        if origin == ORIGIN_CLIENT and _is_control_id(request_id):
            # The client cannot claim our namespace. A protocol fault and not a
            # refusal, because a client that knows to send this is not making
            # an ordinary mistake.
            self._close("MALFORMED_CLIENT",
                        "the client used the proxy's control id namespace")
            return False
        if origin == ORIGIN_CLIENT and not handshake.client_method_known(method):
            self._core._emit("ADMISSION_REFUSED", request_id,
                             reason="UNINSPECTED_METHOD", method_known=False)
            return False
        identity = key(origin, request_id)
        if identity in self._tombstones:
            # A cancelled id is refused for the rest of the session. The request
            # it named is gone and a reply to it would be a reply to nothing.
            return False
        if identity in self._pending:
            if origin == ORIGIN_CLIENT:
                self._close("MALFORMED_CLIENT",
                            "the client reused an id that was already pending")
            else:
                self._close("MALFORMED_UPSTREAM",
                            "upstream reused an id that was already pending")
            return False
        # T6.R6 stores an id with its GENERATION. A cancelled id is tombstoned
        # for the session, but a COMPLETED one may legitimately be used again,
        # and without a generation the core refuses the second request because
        # it has already settled that identity. The generation is what makes
        # "the same id, a later request" a different item rather than a repeat.
        self._generation[identity] = self._generation.get(identity, 0) + 1
        self._pending[identity] = method
        self._core.admit(self._core_key(identity), method=method, origin=origin)
        return True

    def _core_key(self, identity):
        return identity + (self._generation.get(identity, 0),)

    def expects(self, request_id, *, origin):
        return key(origin, request_id) in self._pending

    def expected_method(self, request_id, *, origin):
        return self._pending.get(key(origin, request_id))

    # ── responses ───────────────────────────────────────────────────────────
    def deliver_response(self, *, origin, request_id, frame=None):
        """T6.R1 and T6.R2. One answer, to the right owner, or the session ends.

        A response from upstream answers a CLIENT request; that is the direction
        the id belongs to, and looking it up under the upstream origin is how a
        pump convinces itself an unsolicited response was expected.
        """
        if self._closed:
            return None
        owner = ORIGIN_CLIENT if origin == ORIGIN_UPSTREAM else ORIGIN_UPSTREAM
        identity = key(owner, request_id)
        if identity not in self._pending:
            # T6.R6. Unsolicited or already answered. Either way nobody is
            # waiting for it, and T7.R1 makes that a protocol fault.
            self._close("MALFORMED_UPSTREAM" if origin == ORIGIN_UPSTREAM
                        else "MALFORMED_CLIENT",
                        "a response arrived for an id that is not pending")
            return None

        if frame is not None and not self._shape_matches(identity, frame):
            self._close("MALFORMED_UPSTREAM",
                        "the response shape does not match the request it "
                        "claims to answer")
            return None

        self._pending.pop(identity)
        self._answered.add(identity)
        self._core.settle(self._core_key(identity), Cause("CLEAN", "S1"))

        # T2.R5, and CB06. A fully inspected, authorised upstream ERROR keeps
        # disposition CLEAN and is forwarded AS IT IS, with its own code, message
        # and data. Rebuilding it as a result would answer an error with a
        # success, and replacing it with our own error would tell the client we
        # withheld something when the server simply said no.
        if frame is not None and "error" in frame:
            return frame
        # T6.R1: C's TYPED id, returned as it was issued.
        return {"jsonrpc": "2.0", "id": request_id, "result": (frame or {}).get(
            "result", {})}

    # T2. The member a result MUST carry, per the method that asked for it.
    _REQUIRED_RESULT_MEMBER = {
        "tools/call": "content",
        "tools/list": "tools",
        "resources/read": "contents",
        # prompts/get had NO ROW, so every shape answered it, including `{}`
        # and `7`. A missing row reads as "nothing required" and is the
        # quietest way for a schema check to check nothing.
        "prompts/get": "messages",
    }

    # Each member is a list of OBJECTS, and `content` blocks are discriminated
    # by a string `type`. A container test that stops at "is it a list" accepts
    # `[{}]` and `[7]`, and an inspection of those is vacuously clean: there is
    # nothing to read, so nothing is found, and the client receives a result
    # nobody looked at.
    _TYPED_MEMBERS = frozenset({"content"})

    def _shape_matches(self, identity, frame):
        """T2 and G2-10. What a result must look like, GIVEN the request.

        This is the check that needed the pending METHOD, and the reason `_owed`
        storing a bare timestamp made it impossible: a response is only well
        formed relative to the request it answers.

        The first version only rejected a required member of the WRONG TYPE and
        accepted one that was missing entirely, or a result that was not an
        object at all. Those are the same fault and the milder-looking spelling
        is the more dangerous one: a `tools/call` answered with `{}` has no
        content to inspect, so an inspection of it is vacuously clean and the
        client receives a result nobody read. ASTRA's F08 is four cases and all
        four were accepted.
        """
        if "error" in frame:
            # T2.R5. An error is a legitimate answer and has no result member.
            return True
        method = self._pending.get(identity)
        required = self._REQUIRED_RESULT_MEMBER.get(method)
        if required is None:
            return True
        result = frame.get("result")
        if not isinstance(result, dict):
            return False              # 7, [], a string: not a result object
        if required not in result:
            return False              # {} answering a tools/call
        items = result[required]
        if not isinstance(items, list):
            return False
        for item in items:
            if not isinstance(item, dict):
                return False          # contents: [7]
            if required in self._TYPED_MEMBERS and not isinstance(
                    item.get("type"), str):
                return False          # content: [{}], a block of no kind
        return True

    def settle_from(self, origin, request_id, reason, rule):
        """T6.R3. An upstream REQUEST is answered in U's id namespace, never C's."""
        identity = key(origin, request_id)
        if identity not in self._pending:
            return None
        self._pending.pop(identity)
        self._answered.add(identity)
        return self._core.settle(self._core_key(identity), Cause(reason, rule))

    def cancel(self, request_id, *, origin):
        """T6.R5 and T6.R6. The id is retired and tombstoned for the session."""
        identity = key(origin, request_id)
        self._pending.pop(identity, None)
        self._remember_tombstone(identity)
        if self._closed:
            # The tombstone table overflowed and the session closed inside this
            # call. The item is already settled by the teardown, and settling it
            # again would raise `Settled` out of an ordinary cancellation.
            return identity
        self._core.settle(self._core_key(identity), Cause("REQUEST_CANCELLED", "S6"))
        return identity

    def _remember_tombstone(self, identity):
        if self._closed:
            return
        self._tombstones.append(identity)
        if len(self._tombstones) > TOMBSTONE_LIMIT:
            # T6.R6 caps this; overflow closes the session rather than silently
            # forgetting, because a forgotten tombstone lets a cancelled id be
            # reused and that is the thing the table exists to prevent.
            # T6.R7. OVERLOADED is a resource breach, so S3 and not S5: the
            # peer has not violated the protocol, we have run out of room to
            # keep promises in. And the close must not RAISE on the way out,
            # because `cancel` is a normal operation and a session that has just
            # decided to shut down should not also crash its caller.
            self._close("OVERLOADED", "the tombstone table overflowed",
                        rule="S3")

    # ── the process behind the pipe ────────────────────────────────────────
    def attach_upstream(self, handle, pgid=None):
        """The handle whose EXIT is the signal, for when it arrives later.

        T7.R1 makes an upstream exit with pending calls an S5 fault, and the
        pipe cannot report it: a leader that spawns a grandchild and exits
        leaves the write end open, so the reader waits on a stream that will
        never EOF for a server that is already dead. That is not a slow server
        and the difference must be decided by PROCESS facts, never by silence,
        because an inactivity deadline cannot tell a dead leader from a healthy
        one thinking hard and would eventually fire on both.
        """
        self._upstream = handle
        self._pgid = pgid if pgid is not None else getattr(handle, "pid", None)
        return self

    def _watch_upstream(self):
        """Wait on the HANDLE, not on the pipe, and act the moment it exits."""
        handle = self._upstream
        if handle is None:
            return
        try:
            handle.wait()
        except Exception:                                   # pragma: no cover
            return
        if self._closed or not self._pending:
            return
        # T7.R1, then T8.R12. The fault is recorded first so the cause is the
        # exit rather than whatever the kill produces, and the group is then
        # stopped, which closes the descendant's copy of the write end and is
        # what actually releases the reader.
        # _close supervises now, so the group is stopped as part of the
        # teardown rather than beside it. Doing it twice was how the close
        # could be claimed before anything had actually been stopped.
        self._close("MALFORMED_UPSTREAM",
                    "the upstream process exited with calls still pending")

    # ── reading ─────────────────────────────────────────────────────────────
    def read_upstream(self, stream, inspect=None):
        """Yield the frames a client should see. Stops for good at a fault.

        `inspect` is the seam the result direction needs and defaults to None,
        which is this method exactly as it was. When it is given it is called
        BEFORE the settlement, never after, because T6.R2 allows one outcome
        per held item and a scan that runs after delivery can only ever be a
        second one. It returns None to deliver the original, or a triple
        (replacement, reason, rule) to withhold: the replacement is the one
        answer the client gets, or None for a notification, which has nowhere
        to put an answer.

        T7.R2's last sentence is the whole design: never resynchronise at the
        next newline. Everything after a frame we could not trust is discarded
        WITHOUT being parsed, because parsing it is how a proxy talks itself
        into continuing.
        """
        if self._strict and self._upstream is None:
            # A STARTUP ERROR, not a quieter mode. An upstream nobody supervises
            # is precisely the hang above, and a proxy that runs anyway has
            # chosen to be unable to notice its server dying.
            raise UnsupervisedUpstream(
                "strict mode needs the upstream handle: pass it to Session() or "
                "attach_upstream() before reading, because an exit cannot be "
                "observed on the pipe")
        if self._upstream is not None and self._watcher is None:
            self._watcher = threading.Thread(target=self._watch_upstream,
                                             daemon=True)
            self._watcher.start()

        for raw in framing.bounded_lines(_as_reader(stream),
                                         framing.MAX_FRAME_BYTES):
            if self._closed:
                return
            if parsed_ok_but_unterminated(raw):
                # C15 and T1.R2. The transport is newline delimited, so a
                # trailing fragment at EOF is not a short frame, it is the
                # beginning of one that never arrived. Forwarding it hands the
                # client a truncated message as a complete answer, and the one
                # place that is certain to happen is a server dying mid write.
                self._close("MALFORMED_UPSTREAM",
                            "the last frame ended without its terminator")
                yield from self._drain_refusals()
                return
            parsed = framing.parse_frame(raw, origin=ORIGIN_UPSTREAM)
            if not parsed:
                # The BUDGET travels with the cause. T8's rows name which bound
                # broke, and an answer that says OVER_BUDGET without saying
                # which one cannot be graded against a fixture.
                self._close(parsed.reason, parsed.detail, rule=parsed.rule,
                            budget=parsed.budget)
                yield from self._drain_refusals()
                return
            message = parsed.message

            # T2.R15. A frame carrying BOTH a method and an id is an upstream
            # REQUEST, not a response, however much its id resembles one of
            # ours. G2-15 shares the client's id on purpose. Treating it as the
            # response settled the client's item on a frame the client never
            # asked for, and yielded the server's request toward the client,
            # which is upstream driving the client through us.
            if "method" in message and "id" in message:
                self._core._emit("UPSTREAM_REQUEST_REFUSED", message["id"],
                                 reason="UNINSPECTED_METHOD")
                # T6.R3 and T2.R15. ONE response, to UPSTREAM, in upstream's
                # own id namespace. Dropping it silently was half the row: the
                # client is correctly never told, but the server is left
                # waiting for an answer to a request it is entitled to have
                # refused, and a server blocked on sampling/createMessage
                # stops serving the calls the client actually made. Refusing
                # is the mediation; silence is a hang.
                self._respond_upstream(message["id"], "UNINSPECTED_METHOD")
                continue

            if "id" not in message:
                # T1.R3's last sentence. A notification outside the frozen set
                # is NOT forwarded. The helper existed and this loop did not
                # call it, which is the whole shape of ASTRA's round 4 finding:
                # a component that is correct and never invoked protects
                # nothing.
                method = message.get("method")
                if not handshake.notification_supported(method):
                    self._core._emit("NOTIFICATION_DROPPED", None,
                                     supported=False)
                    continue
                verdict = inspect(raw, message) if inspect is not None else None
                if verdict is not None:
                    # T2.R12. Dropped with a receipt and never a response,
                    # because a notification has no id to answer in.
                    self._core._emit("NOTIFICATION_DROPPED", None,
                                     supported=True)
                    continue
                yield raw
                continue

            # T2.R6. OUR OWN control traffic, handed to the collector and never
            # yielded toward the client, who asked once and is not part of this
            # conversation. Checked before the client correlation because the
            # two namespaces share one table and only the key tells them apart,
            # and BEFORE the inspection because a page of our own tool list is
            # not a message held on the client's behalf: the collector scans
            # every page itself under T5.R3(c).
            #
            # The hand-off is an assignment into a dict the collector reads. It
            # CANNOT BLOCK, which is the point: the collector runs on the
            # thread serving the client's call, and a reader that waited for it
            # to take a page would stall the pump on a stuck consumer. The pump
            # is the thing that would otherwise notice the upstream dying.
            if self.expects(message["id"], origin=ORIGIN_PROXY):
                identity = key(ORIGIN_PROXY, message["id"])
                self._pending.pop(identity)
                self._answered.add(identity)
                self._control_answers[identity] = message
                continue

            # T2.R2 and T2.R4/R5. The inspection happens here, before either
            # the initialize negotiation or the ordinary delivery, so the
            # settlement below is the FIRST and only one for this item.
            verdict = inspect(raw, message) if inspect is not None else None
            if verdict is not None:
                replacement, reason, rule = verdict
                self.settle_from(ORIGIN_CLIENT, message["id"], reason, rule)
                if replacement is not None:
                    yield replacement
                continue
                continue

            if self.expected_method(message["id"], origin=ORIGIN_CLIENT) == \
                    "initialize" and "result" in message:
                forwarded = self._initialize_result(message, raw)
                if forwarded is None:
                    yield from self._drain_refusals()
                    return
                yield forwarded
                continue

            # T6.R5. A response for an id that was cancelled is DISCARDED and
            # the session stays serviceable. It is not an unsolicited response:
            # we did issue that request, we simply stopped waiting. Closing S5
            # here would let any peer end a session by answering a cancellation
            # slightly too late, which is ordinary timing rather than an attack.
            if key(ORIGIN_CLIENT, message["id"]) in self._tombstones:
                self._core._emit("DISCARDED_LATE", message["id"],
                                 reason="the id was cancelled before this arrived")
                continue

            answer = self.deliver_response(origin=ORIGIN_UPSTREAM,
                                           request_id=message["id"],
                                           frame=message)
            if answer is None:
                yield from self._drain_refusals()
                return
            yield raw

        # T7.R1. EOF is not a clean ending while the client is still owed.
        if self._pending and not self._closed:
            self._close("MALFORMED_UPSTREAM",
                        "upstream exited with calls still pending")
        # T4.R7 and T6.R1. The client is WAITING, whoever closed the session
        # and whenever. Recording the fault and saying nothing leaves it
        # waiting for ever on a session that has already decided it is over, so
        # every retained debt is paid here, including the ones a watcher thread
        # recorded while this reader was blocked on the pipe.
        yield from self._drain_refusals()

    def _initialize_result(self, message, raw):
        """T1.R2 and T1.R3, on the one frame where they apply.

        Negotiation and the capability intersection are not advisory helpers a
        reader may consult. The version decides whether the session may
        continue at all, and the capability set decides what the client is told
        it can do. Forwarding an initialize result unread hands both decisions
        to the server, which is exactly the arrangement a mediator exists to
        replace.

        Returns the bytes to forward, or None when the session has closed.
        """
        import json as _json

        result = message.get("result")
        capabilities = result.get("capabilities") if isinstance(result, dict) else None
        if not isinstance(result, dict) or (capabilities is not None
                                            and not isinstance(capabilities, dict)):
            # C09. `7` and `{"capabilities": 7}` reached negotiate() and
            # advertise() and came back out as AttributeError. A malformed
            # frame is a protocol fault with a named cause, and a traceback
            # escaping the reader is not a teardown: nothing is settled, the
            # client is told nothing, and the exception surfaces wherever the
            # caller happens to be standing.
            self._close("MALFORMED_UPSTREAM",
                        "the initialize result is not a result object")
            return None
        negotiated = handshake.negotiate(result)
        if not negotiated.ok:
            self._close(negotiated.reason,
                        "the server offered a protocol version outside the "
                        "frozen set",
                        rule="S3")
            return None

        filtered = handshake.advertise(result.get("capabilities") or {})
        if filtered != (result.get("capabilities") or {}):
            self._core._emit("CAPABILITIES_FILTERED", message.get("id"),
                             advertised=sorted(filtered))
        rebuilt = dict(message)
        rebuilt["result"] = dict(result, capabilities=filtered)

        self.deliver_response(origin=ORIGIN_UPSTREAM,
                              request_id=message["id"], frame=rebuilt)
        if self._closed:
            return None
        return (_json.dumps(rebuilt, separators=(",", ":")) + "\n").encode()

    def _respond_upstream(self, request_id, reason, rule="S1"):
        """T6.R3. The refusal goes back up the pipe it came down.

        Best effort and bounded: a server whose stdin has already closed cannot
        be told anything, and failing to tell it is not a reason to tear down a
        session that is otherwise healthy.
        """
        import json as _json

        handle = self._upstream
        stdin = getattr(handle, "stdin", None) if handle is not None else None
        if stdin is None:
            return
        body = {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": -32070, "message": "SUNGLASSES_WITHHELD",
                          "data": {"reason_code": reason, "rule": rule}}}
        try:
            stdin.write((_json.dumps(body, separators=(",", ":"))
                         + "\n").encode("utf-8"))
            stdin.flush()
        except (OSError, ValueError):
            self._core._emit("UPSTREAM_REQUEST_REFUSED", request_id,
                             reason="write_failed")

    def _client_refusal(self, identity, reason, rule):
        """One JSON-RPC error to the client, in the id it used."""
        import json as _json

        _origin, _type_name, request_id = identity[0], identity[1], identity[2]
        return (_json.dumps({
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32070, "message": "SUNGLASSES_WITHHELD",
                      "data": {"reason_code": reason, "rule": rule}},
        }, separators=(",", ":")) + "\n").encode()

    # ── outcome ─────────────────────────────────────────────────────────────
    def _close(self, reason, detail, rule="S5", budget=None):
        """Tear down once, supervise the processes, and RETAIN what is owed.

        Two things were missing and they were the same mistake twice.

        The teardown ran with no supervisor, so a protocol fault settled every
        item and stopped nothing: the child was still alive afterwards holding
        the pipes (C06), and the core could not tell a completed teardown from
        one whose supervisor failed, because it was never given one to fail
        (C11). The core already refuses to claim closure over a supervisor that
        returns False; it was simply never handed one.

        And the pending table was CLEARED here, which is the only record of who
        is still waiting. Whoever closed the session first won, and the reader
        that reached the exit afterwards found nothing owed and said nothing to
        a client that is still blocked on a request (C05, C07). The owed
        refusals are retained on the session now and drained by the reader on
        its way out, so the close records the debt and the exit pays it.
        """
        with self._settlement:
            if self._closed:
                return
            self._closed = (reason, rule)
            # THE DEBT IS RECORDED BEFORE THE TEARDOWN, not after it. The
            # teardown supervises, which blocks for up to the kill grace, and
            # stopping the group is exactly what releases the reader waiting on
            # the pipe. Recording afterwards left a window in which the reader
            # woke, found `_closed` set, `_pending` cleared and the debt not yet
            # written, and delivered nothing to a client still blocked on its
            # request. One owner, one lock, and the write happens first.
            self._owed_refusals.extend(
                (identity, reason, rule) for identity in self._pending
                if identity[0] == ORIGIN_CLIENT)
            self._pending.clear()
        self._core.teardown(Cause(reason, rule, budget=budget, detail=detail),
                            stop_processes=self._stop_processes())

    def _stop_processes(self):
        """The supervisor callback, or None when there is nothing supervised.

        None is not a quieter kind of success. T8.R12 and the core's own
        teardown treat a missing supervisor as "this caller stopped nothing",
        which is why an API session with no handle records SESSION_TORN_DOWN
        and never UPSTREAM_CLOSED (C12).
        """
        if self._upstream is None and self._pgid is None:
            return None
        target = self._pgid if self._pgid is not None else self._upstream.pid

        def stop():
            return supervisor.stop_group(target, grace_ms=250,
                                         handle=self._upstream)
        return stop

    def _drain_refusals(self):
        """T6.R1. Each retained refusal is handed over exactly once."""
        while True:
            with self._settlement:
                if not self._owed_refusals:
                    return
                identity, reason, rule = self._owed_refusals.pop(0)
            yield self._client_refusal(identity, reason, rule)

    def control_answer(self, request_id):
        """The frame a proxy-owned request got, or None while it is unanswered."""
        return self._control_answers.get(key(ORIGIN_PROXY, request_id))

    def closed_with(self):
        return self._closed

    def answer_for(self, request_id, *, origin):
        return self._core.settled_as(self._core_key(key(origin, request_id)))

    @property
    def events(self):
        return self._core.events


def _as_reader(stream):
    """Accept bytes or a file object, so a caller need not wrap a fixture."""
    if hasattr(stream, "read"):
        return stream
    import io
    return io.BytesIO(stream)
