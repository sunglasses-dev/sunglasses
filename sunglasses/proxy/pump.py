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
from .session import Cause, Session as CoreSession, Settled

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


# RC01. What each method's list members must ACTUALLY contain. A container test
# that stops at "is it a list of objects" accepts a text block with no text, a
# tool with no name and a prompt message with no role, and an inspection of any
# of those is vacuously clean: there is nothing to read, so nothing is found,
# and the client receives a result nobody could have looked at.
_TEXT_KINDS = frozenset({"text"})
_PROMPT_ROLES = frozenset({"user", "assistant"})


def _text_block_is_complete(block):
    """One content block, to the bottom.

    A block is a discriminated union and the discriminant decides what else has
    to be there. `{"type": "text"}` with no text and `{"type": "text", "text":
    7}` are both a block that carries nothing a scanner can read, and an
    inspection of either is vacuously clean.
    """
    if not isinstance(block, dict):
        return False
    kind = block.get("type")
    if not isinstance(kind, str):
        return False
    if kind == "text":
        return isinstance(block.get("text"), str)
    if kind == "resource":
        resource = block.get("resource")
        if not isinstance(resource, dict) or not isinstance(
                resource.get("uri"), str):
            return False
        # An embedded resource carries text or it carries bytes. Neither means
        # the block names a resource and encloses nothing, which is a reference
        # the client cannot follow and the scanner cannot read.
        if "blob" in resource:
            return isinstance(resource.get("blob"), str)
        return isinstance(resource.get("text"), str)
    # image and audio are refused as UNSUPPORTED_CONTENT by the selector, so
    # the schema only insists they are shaped like content blocks at all.
    return True


# RC11. MCP 2025-06-18 FIXES these shapes; the guard checked that the
# discriminant was a string and stopped. `{"type": "array"}` is a well-formed
# JSON Schema and a malformed TOOL, and five bodies like it passed the reader,
# yielded the original to the client and settled CLEAN.
#
# Each entry is a member that MAY be absent and, when present, has exactly one
# type. Absent optional members are not a fault; a member declared with the
# wrong type is, which is the difference between checking presence and checking
# the schema. Unknown members pass, because the spec allows extensions and a
# guard that refuses them would refuse conformant servers.
_TOOL_MEMBERS = {
    "name": str, "title": str, "description": str,
    "inputSchema": dict, "outputSchema": dict,
    "annotations": dict, "_meta": dict,
}
_SCHEMA_MEMBERS = {
    "type": str, "properties": dict, "required": list,
    "title": str, "description": str,
}

# RC16. MCP fixes these too, and the guard stopped at the tool's own members.
# `annotations` is a hint object the CLIENT is expected to read -- a title it
# shows a user, and booleans it may use to decide whether a call is safe to
# repeat -- so a number where a boolean belongs is a hint nobody can act on and
# a number where the title belongs is a label that cannot be displayed.
_ANNOTATION_MEMBERS = {
    "title": str, "readOnlyHint": bool, "destructiveHint": bool,
    "idempotentHint": bool, "openWorldHint": bool,
}


def _declared_members_typed(item, members):
    """Every DECLARED member's type, not only the discriminant's presence."""
    if not isinstance(item, dict):
        return False
    for name, kind in members.items():
        if name in item and not isinstance(item[name], kind):
            return False
    return True


def _tool_is_complete(item):
    """RC16. EVERY declared member, to its own shape, not just the one ASTRA
    named first.

    RC08 fixed the discriminated bodies, RC11 fixed the input schema, and seven
    more shapes still settled CLEAN: an output schema that is not an object
    schema, a property whose schema is a number, an annotation title that is a
    number, a boolean hint that is a number. The pattern is the same one this
    package keeps paying for -- a member was checked because it had been named
    in a finding, rather than because the spec fixes its type.
    """
    if not _declared_members_typed(item, _TOOL_MEMBERS):
        return False
    if not _input_schema_is_complete(item.get("inputSchema")):
        return False
    # Declared and optional. Absent is fine; present and malformed is not.
    if "outputSchema" in item and not _input_schema_is_complete(
            item.get("outputSchema")):
        return False
    if "annotations" in item and not _declared_members_typed(
            item.get("annotations"), _ANNOTATION_MEMBERS):
        return False
    return True


def _input_schema_is_complete(schema):
    """A tool's input schema is an OBJECT schema, per MCP 2025-06-18.

    `type` is fixed to the literal "object" rather than "some string": the spec
    does not leave the choice open, and a tool advertising an array or a string
    at the top of its input schema is not a tool a client can call. `required`
    is an array OF STRINGS, so `[7]` names no property; `properties` is an
    object, so a list describes no properties at all. Each of those three is a
    body ASTRA sent that settled CLEAN.
    """
    if not isinstance(schema, dict):
        return False
    if schema.get("type") != "object":
        return False
    if not _declared_members_typed(schema, _SCHEMA_MEMBERS):
        return False
    required = schema.get("required")
    if required is not None and not all(
            isinstance(name, str) for name in required):
        return False
    # RC16. A property's VALUE is a schema. `{"review": 7}` declares a property
    # whose shape is the number seven, which describes nothing a client could
    # build and nothing an approval could quote.
    properties = schema.get("properties")
    if properties is not None and not all(
            isinstance(member, dict) for member in properties.values()):
        return False
    return True


def _member_is_complete(method, item):
    """One list member of one method's result, checked against its own shape."""
    if method == "tools/call":
        return _text_block_is_complete(item)
    if method == "tools/list":
        if not isinstance(item.get("name"), str):
            return False                      # a tool nobody can call
        # REQUIRED, and shaped as the SPEC fixes it, not merely present. A
        # tool whose input schema is absent, null or `{}` describes nothing
        # about what it accepts, and an approval over that descriptor approves
        # a shape nobody stated.
        return _tool_is_complete(item)
    if method == "resources/read":
        if not isinstance(item.get("uri"), str):
            return False
        if "blob" in item:
            return isinstance(item.get("blob"), str)
        return isinstance(item.get("text"), str)
    if method == "prompts/get":
        role = item.get("role")
        # `in` on a frozenset raises TypeError for a list or a dict, and an
        # unhashable role is exactly what an attacker sends to find out what
        # happens. A traceback out of the reader is not a teardown: nothing is
        # settled and the client is told nothing.
        if not isinstance(role, str) or role not in _PROMPT_ROLES:
            return False
        return _text_block_is_complete(item.get("content"))
    return True


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
        # RC13. Items that have LEFT `_pending` and have not yet reached the
        # core. Without this set there is a moment when a request is in neither
        # table, and a close that lands in it records no debt for a client who
        # is still waiting. The core settlement cannot be made part of the
        # locked step -- holding this lock across a call into the core would
        # park the watcher's close behind the reader, and the close is what
        # stops the processes -- so the window is CLOSED BY A RECORD instead.
        self._settling: set = set()
        # RC17. identity -> the core key whose generation this record answers.
        self._settling_key: dict = {}
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
        # RC17. The record is part of the pending state, so admission reads it.
        # An id whose previous generation is still mid-handoff is not free: the
        # old response would settle the new request, which answers a call the
        # client never made with a result from one it did.
        # RC20. These two reads stay SEPARATE and in this order, because the
        # reader moves an entry between the tables they look at and the fix is
        # not to merge them -- it is to make the INSERT re-check under the lock,
        # below. Merging them here would short-circuit before the pending test
        # and change which refusal a caller gets.
        #
        # This also corrects a comment I wrote at the generation lookup calling
        # it unreachable "while admission refuses a still-settling id". That
        # assumed admission was atomic. It is not: an admission can pass the
        # settling test, pause, and find `_pending` empty because the reader
        # moved the entry in between. RC20 reaches the lookup through ordinary
        # operations and it is load-bearing.
        if identity in self._settling:
            if origin == ORIGIN_CLIENT:
                self._close("MALFORMED_CLIENT",
                            "the client reused an id whose previous request is "
                            "still being answered")
            else:
                self._close("MALFORMED_UPSTREAM",
                            "upstream reused an id whose previous request is "
                            "still being answered")
            return False
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
        # RC20. The INSERT happens under the same lock as the test, re-checking
        # both tables, so nothing can move an entry between deciding and
        # recording.
        with self._settlement:
            if identity in self._settling or identity in self._pending:
                return False
            self._generation[identity] = self._generation.get(identity, 0) + 1
            self._pending[identity] = method
        self._core.admit(self._core_key(identity), method=method, origin=origin)
        if self._closed:
            # RC06. The session closed while this admission was in flight, so
            # the item was admitted into a table that has already been torn
            # down and nothing will ever settle it. Reporting success would
            # hand the caller a request the session has no intention of
            # answering.
            self._pending.pop(identity, None)
            return False
        return True

    def _core_key(self, identity):
        return identity + (self._generation.get(identity, 0),)

    def expects(self, request_id, *, origin):
        return key(origin, request_id) in self._pending

    def expected_method(self, request_id, *, origin):
        return self._pending.get(key(origin, request_id))

    # ── responses ───────────────────────────────────────────────────────────
    def deliver_response(self, *, origin, request_id, frame=None,
                         defer_retire=False):
        """T6.R1 and T6.R2. One answer, to the right owner, or the session ends.

        A response from upstream answers a CLIENT request; that is the direction
        the id belongs to, and looking it up under the upstream origin is how a
        pump convinces itself an unsolicited response was expected.

        `defer_retire` says WHO completes the wire handoff. RC14's obligation
        lasts until the frame reaches the client, and where that happens
        depends on the caller: a direct caller has the frame the moment this
        returns, so the handoff is done; the reader has only a value it still
        has to yield, so it keeps the record and retires it afterwards. Getting
        this wrong in the quiet direction leaves a record nobody ever drops,
        which keeps the watcher awake and blocks the id for the session.
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

        with self._settlement:
            # RC09. ONE OWNER for removing a pending entry, and it is this
            # lock. The shape check above takes real time, and an upstream that
            # exits during it makes the watcher close the session and clear the
            # table underneath us: the pop then raised KeyError out of the
            # reader, which is not a teardown. Nothing is settled, the exit
            # drain never runs, and the client that is still waiting receives
            # not one frame but none.
            #
            # If the close won, it has already recorded this item's debt and
            # the reader pays it on the way out. Delivering here as well would
            # be the second answer T6.R1 forbids.
            if self._closed or identity not in self._pending:
                return None
            self._pending.pop(identity)
            self._answered.add(identity)
            # RC13. The entry leaves `_pending` and the RECORD takes its place
            # in the same locked step, so there is no instant in which this
            # request is in neither. A close that wins now finds it in
            # `_settling`, records the debt, and the reader delivers nothing.
            self._settling.add(identity)
            self._settling_key[identity] = self._core_key(identity)
        if not self._settle_outside_lock(identity):
            return None

        # T2.R5, and CB06. A fully inspected, authorised upstream ERROR keeps
        # disposition CLEAN and is forwarded AS IT IS, with its own code, message
        # and data. Rebuilding it as a result would answer an error with a
        # success, and replacing it with our own error would tell the client we
        # withheld something when the server simply said no.
        if not defer_retire:
            self._retire_record(identity)
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
        result = frame.get("result")
        if method == "initialize":
            # RC01. `initialize` has no list member, so the container test
            # never reached it: a result with a version and capabilities and
            # NO serverInfo was accepted, which is the frame the whole session
            # identity is built on.
            info = result.get("serverInfo") if isinstance(result, dict) else None
            # serverInfo has to NAME the server and its version. An empty
            # object satisfies "is a dict" and identifies nothing, and T1.R1
            # builds the session identity out of exactly this.
            return (isinstance(result, dict)
                    and isinstance(result.get("protocolVersion"), str)
                    and isinstance(result.get("capabilities"), dict)
                    and isinstance(info, dict)
                    and isinstance(info.get("name"), str)
                    and isinstance(info.get("version"), str))
        required = self._REQUIRED_RESULT_MEMBER.get(method)
        if required is None:
            return True
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
            if not _member_is_complete(method, item):
                return False
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
        # RC15. PENDING UNION SETTLING. The watcher returned when `_pending`
        # was empty without looking at the record, so with one item mid-handoff
        # and nothing pending a child exit closed nothing: the session went on
        # forwarding after an unobserved fatal exit. An item in `_settling` is
        # a client still waiting, which is the whole reason the record exists.
        if self._closed or not (self._pending or self._settling):
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
    def read_upstream(self, stream):
        """Yield the frames a client should see. Stops for good at a fault.

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
                # RC02/RC07. Closure can win the race with a frame that is
                # already buffered: a watcher observes the exit, or the reader
                # itself closes, while bytes are still in flight. Returning
                # here without paying the debt loses the client's one answer
                # for a reason nobody can see from the outside, which is the
                # hang F15 ruled against arriving by a different door.
                yield from self._drain_refusals()
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
                yield raw
                continue

            # T2.R6. OUR OWN control traffic, handed to the collector and never
            # yielded toward the client, who asked once and is not part of this
            # conversation. Checked before the client correlation because the
            # two namespaces share one table and only the key tells them apart.
            #
            # The hand-off is an assignment into a dict the collector reads. It
            # CANNOT BLOCK, which is the point: the collector runs on the
            # thread serving the client's call, and a reader that waited for it
            # to take a page would stall the pump on a stuck consumer. The pump
            # is the thing that would otherwise notice the upstream dying.
            if self.expects(message["id"], origin=ORIGIN_PROXY):
                identity = key(ORIGIN_PROXY, message["id"])
                # RC12. One owner for removing a pending entry means ONE
                # owner, and this was the last door left open. `expects` can
                # return true and the upstream can die before the pop: the
                # watcher closed the session and cleared the table underneath
                # this line, and the pop raised KeyError out of the reader.
                # That is not a teardown. Nothing was delivered, the exit drain
                # never ran, and the client waiting on its own call got no
                # frame at all.
                with self._settlement:
                    if self._closed or identity not in self._pending:
                        # The close won and has already recorded whatever debt
                        # there was. This control page is ours, nobody is
                        # blocked on it, and handing it over now would put an
                        # answer in the collector for a session that is gone.
                        continue
                    self._pending.pop(identity)
                    self._answered.add(identity)
                    self._control_answers[identity] = message
                    self._settling.add(identity)
                    self._settling_key[identity] = self._core_key(identity)
                # RC05. The CORE owns the item too, so an answered control
                # request has to settle there as well. Leaving it owed means a
                # session that finished its work still reports an outstanding
                # correlation, and T9.R5 reads an ADMITTED with no SETTLED as
                # INCOMPLETE_SESSION. RC13's discipline applies here too: the
                # call happens outside the lock, and the record left behind
                # keeps the window closed.
                self._settle_outside_lock(identity)
                # No wire handoff for a control page: nobody is waiting on it,
                # so the obligation ends with the settlement.
                self._retire_record(identity)
                continue

            if self.expected_method(message["id"], origin=ORIGIN_CLIENT) == \
                    "initialize" and "result" in message:
                init_identity = key(ORIGIN_CLIENT, message["id"])
                init_key = self._core_key(init_identity)
                forwarded = self._initialize_result(message, raw)
                if forwarded is None:
                    yield from self._drain_refusals()
                    return
                # RC21/RC22. Initialize returns to the READER like every other
                # response, so it owns the same handoff and was using the
                # direct-caller retirement instead: one frame for two requests,
                # and with no second request the watcher returned without
                # closing and the reader forwarded after a real exit.
                yield self._handoff(init_identity, forwarded, init_key)
                if self._closed:
                    yield from self._drain_refusals()
                    return
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

            # RC25/RC26. The key is captured BEFORE the record is created,
            # and it is EXACT rather than hopeful: a reuse cannot change the
            # generation while the entry is still pending, because
            # `admit_request` refuses an identity that is in `_pending` or in
            # `_settling`, and the entry leaves the first only by entering the
            # second in one locked step. So this is the generation the record
            # about to be created carries -- the one THIS reader owns.
            identity = key(ORIGIN_CLIENT, message["id"])
            record_key = self._core_key(identity)
            answer = self.deliver_response(origin=ORIGIN_UPSTREAM,
                                           request_id=message["id"],
                                           frame=message, defer_retire=True)
            if answer is None:
                yield from self._drain_refusals()
                return
            # RC18/RC19/RC19b. The obligation ends HERE, under the lock, and
            # the yield happens only if this call says the close did not win.
            # The decision is IN the expression, so it is made when this line
            # runs rather than before it. None means the close won and nothing
            # crosses; consumers skip it.
            yield self._handoff(identity, raw, record_key)
            if self._closed:
                yield from self._drain_refusals()
                return
            # IDEMPOTENT, and both halves are load-bearing for different
            # reasons. The gate above removes the record BEFORE the value
            # leaves, because a close landing after delivery must not pay an
            # obligation that is gone (RC19) and an id whose frame is on the
            # wire is free (RC19b). This line is the reader stating that what
            # it handed over is retired, on the advance that proves the
            # consumer came back; by then the removal has already happened, so
            # it takes nothing away and removes nothing twice.
            #
            # RC25/RC26. Retire only what THIS reader created. While the
            # generator was suspended the id may have been reused, and the
            # record standing under this identity then belongs to a LATER
            # generation and another reader. Dropping it here left that
            # reader's obligation unrecorded, and both failures followed from
            # the one deletion: the watcher saw neither a pending entry nor a
            # record and returned without closing on a real child exit (RC25),
            # and admission, which refuses an identity already in `_settling`,
            # found nothing there and let a duplicate in (RC26).
            #
            # An ABSENT record still calls through, because that is the
            # ordinary case -- the handoff above already dropped it -- and the
            # call is idempotent. Only a record belonging to someone else is
            # left alone. There is no window between the test and the call: a
            # record we still own cannot be superseded, since admission refuses
            # an identity while `_settling` holds it.
            self._retire_record(identity, record_key)

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

        # RC21. `defer_retire=True` because this RETURNS TO THE READER, which
        # performs the handoff. It was using the direct-caller retirement, so
        # the obligation ended one step too early and a close landing in that
        # step paid nothing: one frame for two known requests.
        self.deliver_response(origin=ORIGIN_UPSTREAM,
                              request_id=message["id"], frame=rebuilt,
                              defer_retire=True)
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

    def _settle_outside_lock(self, identity):
        """Settle one removed item in the core, and say whether we still owe it.

        The call is made OUTSIDE `_settlement` on purpose. The watcher's close
        is what stops the upstream processes, and parking it behind a reader
        that is mid-settlement is the deadlock version of the bug RC13 names:
        the window would be closed and nothing would ever come through it.
        `_settling` is what makes the step atomic instead.

        Returns False when the close won the race, in which case it has already
        recorded the wire debt and the reader must deliver nothing, or T6.R1's
        one answer becomes two.
        """
        core_key = self._core_key(identity)
        try:
            # RC17. Bound to the generation being ANSWERED, captured when the
            # entry left `_pending`, not re-read now. `_core_key` reads the
            # CURRENT generation, so an id re-admitted while its old generation
            # was still settling had the old response settle the NEW request.
            #
            # DEFENCE IN DEPTH, and the mutation round says so: with admission
            # refusing an id that is still in `_settling`, the generation
            # cannot advance inside this window, so removing this line changes
            # nothing on any reachable path and the mutant survives. It is kept
            # because it is the half that does not depend on the other half
            # being right, and it is written down here rather than covered by a
            # test that would have to reach a state the admission rule forbids.
            core_key = self._settling_key.get(identity, core_key)
            self._core.settle(core_key, Cause("CLEAN", "S1"))
        except Settled:
            # The teardown answered it first. `Settled` means a caller settled
            # an item twice, which is normally its own ordering bug, and this
            # is the one place where it is not: RC13's race is exactly this.
            # Narrowed to a closed session so a genuine double settlement on a
            # LIVE session still raises the way it is meant to.
            if self._closed is None:
                raise
        # RC14. The record is NOT retired here. It is the wire obligation, and
        # the obligation lasts until the frame has actually been handed over:
        # retiring it at the end of the settlement left a gap in which the item
        # was settled CLEAN internally and present in neither table, so a child
        # exit during that gap produced one frame for two known requests. The
        # reader retires it after the yield, and `_close` pays it if the close
        # wins first.
        with self._settlement:
            # The close is WRITTEN under this lock, so whether we still owe the
            # frame is READ under it. Deciding to deliver outside the lock lets
            # the reader commit to a frame at the instant the close is
            # recording the debt for that same item, and T6.R1's one answer
            # becomes two.
            #
            # Also a survivor of the mutation round, and for the same reason as
            # the generation lookup above: the line below re-reads `_closed`,
            # so deleting this one leaves the OUTCOME identical and only widens
            # the window in which the two threads can disagree. A test would
            # have to hit that window rather than assert a behaviour, so the
            # narrowing is recorded here instead of being claimed as covered.
            if self._closed is not None:
                return False
        return self._closed is None



    def _handoff(self, identity, raw, record_key):
        """The single point where an obligation ends, EVALUATED BY THE YIELD.

        RC18 is why this is an expression and not a preceding statement. A
        statement before `yield` runs before the yield LINE is reached, so a
        close arriving at that moment found the record already discharged,
        stood down, and the resumed reader delivered anyway: one original where
        none should have crossed. Inside the yield expression the decision
        happens when the line RUNS, so a close that completes while the reader
        is parked at that line still finds the record owed, wins, and this
        returns `b""` -- nothing crosses.

        `b""` AND NOT `None`, and the docstring says so because the code does.
        A consumer writes what the reader yields, and on a byte stream zero
        bytes IS nothing: it needs no special case. `None` would raise in any
        writer that does not special-case it, which is what a reviewer's
        control does -- it writes the yielded value unconditionally, and with
        `None` it raised TypeError in place of a refusal.

        After the yield there is no line event before the suspension, so a
        close landing there finds the record discharged and does not pay: one
        original and no double answer. Both orders are consistent, which is the
        property; the few bytecodes in between cannot produce two answers.


        RC18, RC19, RC19b, RC21 and RC22 are five shapes of one mistake:
        retirement scattered across callers, each choosing its own moment, so
        the close and the reader disagreed about who still owed a frame.

        Three things have to be true at once, and only a lock makes them so:

          the close must not pay an obligation that is ABOUT to be discharged
          (RC19: exit after the first original reached the wire, close pays it
          again, three frames for two requests);

          the reader must not hand over an original once a close has WON
          (RC18: exit immediately before the yield, close pays it, and the
          reader yields anyway -- three frames again);

          and once the frame is genuinely gone the id is FREE (RC19b: reuse
          after a real handoff, while this generator is suspended at its yield,
          is valid and was being refused MALFORMED_CLIENT).

        Returns False when the close won, in which case the caller yields
        NOTHING and the retained refusal is the client's one answer.
        """
        with self._settlement:
            if self._closed:
                # The close won, so NOTHING CROSSES and the retained refusal it
                # recorded is this client's one answer.
                #
                # Empty bytes rather than None, and the difference is not
                # cosmetic: a consumer writes what the reader yields, and on a
                # byte stream `b""` IS nothing -- it writes zero bytes and
                # needs no special case. `None` would make every consumer,
                # including a reviewer's, carry a check it never needed before,
                # and one that forgets it gets a TypeError in place of a
                # refusal.
                return b""
            # RC25/RC26, and it is a TRIPWIRE rather than a tolerance.
            #
            # Discharging here a record THIS reader did not create would answer
            # one reader's frame by cancelling another reader's debt. The
            # production path cannot reach that today: admission refuses an
            # identity while it is in `_settling`, and the record is created and
            # handed off inside that window, so no reuse can intervene.
            #
            # Which is exactly why the mismatch must FAULT and not be absorbed.
            # A guard that quietly tolerates a state the code calls impossible
            # is a check that skips itself: it would run green forever while the
            # invariant it depends on rotted underneath it. If admission's
            # refusal ever stops holding, the session stops and says so.
            #
            # S3, not S5: the peer has violated nothing, our own invariant has.
            # PRESENT and owned by another generation. An ABSENT record is
            # the ordinary idempotent case, never a fault -- the same reading
            # `_retire_record` takes, where a missing record calls through.
            standing = self._settling_key.get(identity)
            mismatch = standing is not None and standing != record_key
            if not mismatch:
                self._settling.discard(identity)
                self._settling_key.pop(identity, None)
        if mismatch:
            # OUTSIDE the lock. `_close` takes `_settlement` itself and it is
            # not reentrant, so faulting inside the block would deadlock the
            # session instead of ending it. The record is left owed on purpose:
            # the teardown drains `_pending` and `_settling`, so the generation
            # that really owns it is still paid.
            self._close("INTERNAL_FAULT",
                        "a handoff arrived for a record another generation "
                        "owns, so admission's refusal did not hold",
                        rule="S3")
            return b""
        return raw

    def _retire_record(self, identity, record_key=None):
        """RC14. The wire obligation is discharged; drop the record.

        RC25/RC26. `record_key` names WHICH record the caller is discharging --
        the identity together with the generation captured when that record was
        created. A reader may only retire the record it created. While a reader
        is suspended at its yield the id can be reused, and the record standing
        under the identity then belongs to a LATER generation and another
        reader; retiring by identity alone dropped that reader's obligation.
        Both round-7 failures came out of the one deletion: the watcher found
        neither a pending entry nor a record and returned without closing on a
        real child exit (RC25), and admission, which refuses an identity that is
        already in `_settling`, found nothing there and admitted a duplicate
        (RC26).

        The call still HAPPENS in every case, and only the deletion is
        conditional. An absent record is the ordinary case, because the handoff
        has usually dropped it already, and the method has always been
        idempotent on the way out.

        `None` keeps the unconditional meaning for the callers that create and
        retire inside one locked flow, where no reuse can intervene.
        """
        with self._settlement:
            if record_key is not None and \
                    self._settling_key.get(identity, record_key) != record_key:
                # Someone else's record, a later generation's. Leave it owed.
                return
            self._settling.discard(identity)
            self._settling_key.pop(identity, None)

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
            if self._closed and self._core._closed:
                return
            if self._closed:
                # RC04. The session is marked closed but the CORE is not,
                # which happens only when a supervisor returned False and the
                # core refused to claim a teardown it could not complete. A
                # retry must re-supervise rather than return: the group is
                # still up, and the one thing worse than a failed kill is a
                # failed kill nobody tries again.
                self._core.teardown(
                    Cause(reason, rule, budget=budget, detail=detail),
                    stop_processes=self._stop_processes())
                return
            self._closed = (reason, rule)
            # THE DEBT IS RECORDED BEFORE THE TEARDOWN, not after it. The
            # teardown supervises, which blocks for up to the kill grace, and
            # stopping the group is exactly what releases the reader waiting on
            # the pipe. Recording afterwards left a window in which the reader
            # woke, found `_closed` set, `_pending` cleared and the debt not yet
            # written, and delivered nothing to a client still blocked on its
            # request. One owner, one lock, and the write happens first.
            # RC03. Each item keeps the FIRST cause recorded against it. A
            # session-wide MALFORMED_UPSTREAM arriving later does not rewrite
            # an item that already settled S3, S4 or S6: the core keeps the
            # per-item cause and the refusal on the wire has to agree with it,
            # or the receipt and the client's error tell two different stories
            # about the same request.
            # RC13. `_settling` as well as `_pending`: an item whose entry has
            # been removed and whose core settlement has not landed yet is
            # still a client waiting for a frame, and it used to be invisible
            # here. That is the "in neither table" window, seen from the side
            # that pays the debt.
            for identity in list(self._pending) + list(self._settling):
                if identity[0] != ORIGIN_CLIENT:
                    continue
                own = self._core.terminal_cause(self._core_key(identity))
                self._owed_refusals.append(
                    (identity,
                     own.reason if own is not None else reason,
                     own.rule if own is not None else rule))
            self._pending.clear()
            # The debt above is now recorded for both tables, so the record has
            # done its job and must not keep the watcher awake (RC15) or block
            # a later admission (RC17).
            self._settling.clear()
            self._settling_key.clear()
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
