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
import time

from . import bounds, envelope, framing, handshake, selector, supervisor
from .session import Cause, Session as CoreSession, Settled

class Attempt:
    """ONE admission attempt: its identity, the generation it reserved, and the
    cause if it was refused.

    R-179-R5, the fifth round on one theme. Rounds 2 and 4 each fixed the
    instance ASTRA drove and left the next id-keyed call one frame away: a
    refusal table keyed by the id, then a settlement keyed by the id. An id is
    shared by every attempt that ever uses it, so anything an attempt owns has
    to travel with a generation attached, or a later attempt inherits it.

    The token is (origin, id-type, id, generation) and it is IMMUTABLE. A
    holder uses the one it was handed and never re-reads the current
    generation, because "current" is the id-only key wearing a timestamp.
    """

    __slots__ = ("identity", "generation", "cause", "_frozen")

    def __init__(self, identity, generation, cause=None):
        object.__setattr__(self, "_frozen", False)
        self.identity = identity
        self.generation = generation
        self.cause = cause
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, name, value):
        """FROZEN MEANS FROZEN. R-179-R6/R5_IMMUTABLE_ATTEMPT.

        The docstring above has said the token is immutable since round 5, and
        only the TUPLE it returns was: `attempt.generation += 1` changed the
        token every later reader would be handed. A carrier whose contents can
        move is an id-only key with extra steps, which is the defect this whole
        lane is about. `Cause` was frozen for the same reason and by the same
        shape.
        """
        if getattr(self, "_frozen", False):
            raise AttributeError(
                f"an Attempt is immutable once issued; {name!r} names the "
                f"generation a holder was handed and it may not move under it")
        object.__setattr__(self, name, value)

    def __delattr__(self, name):
        """DELETION IS A WRITE, and round 6's guard covered only assignment.

        R-179-R7/(c). `del attempt._frozen` succeeded, and with the guard gone
        `attempt.generation += 1` changed the token every later holder would be
        handed -- so "frozen the way `Cause` is" was false, because `Cause` has
        carried this guard all along. A freeze with a documented way out is a
        convention, not an invariant.
        """
        raise AttributeError(
            f"an Attempt is immutable once issued; {name!r} may not be "
            f"deleted, least of all the flag that freezes it")

    @property
    def token(self):
        return self.identity + (self.generation,)

    @property
    def request_id(self):
        return self.identity[2]

    def __repr__(self):
        reason = f" {self.cause.reason}" if self.cause else ""
        return f"<Attempt {self.token}{reason}>"


def _tell(sink, attempt):
    """Hand a refusal to the ATTEMPT that asked for it, and to nobody else.

    R-179-R4. Three rounds of one bug were one mistake: refusal state kept in a
    table keyed by the ID. Two attempts on the same id share that key, so a
    later attempt overwrote what an earlier one was about to read (XE03), and
    an earlier attempt's answer retired a later attempt's live request (XR03).
    Clearing the entry sooner -- round 3 -- only narrows the window. The id is
    simply the wrong key, because the thing being described is an ATTEMPT.

    So nothing is stored. The caller passes the place its own answer goes, and
    that place is unreachable from any other attempt: there is no table left to
    read at the wrong moment. The boolean return is unchanged, because 165 call
    sites depend on it and exactly one caller needs the cause.
    """
    if sink is not None:
        sink(attempt)


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
# R-168-R6/F1. How many times an answer may be re-derived because an
# authority landed while it was being prepared. The precedence allows two
# changes (None -> DESCRIPTOR_CHANGED -> REQUEST_CANCELLED) and each is
# terminal once accepted, so this is slack above the reachable maximum
# rather than a guess; exhausting it is an INTERNAL_FAULT and never a
# stale answer delivered quietly.
_REDERIVE_LIMIT = 8
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


class _Replaced:
    """What the inspection seam decided should cross INSTEAD of the original.

    A tiny wrapper rather than a bare bytes value because the reader has to
    tell "deliver this instead" apart from "deliver the original", and an
    ordinary frame is already a dict. `frame` may be None, which means the item
    is settled and NOTHING crosses.
    """

    __slots__ = ("frame",)

    def __init__(self, frame):
        self.frame = frame


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
        # identity -> the budget its recorded cause names, or None. Read by
        # `_client_refusal`, which the envelope requires to name a bound for
        # OVER_BUDGET and to name none for anything else.
        self._budget_for: dict = {}
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
        # R-168-R3. The release gate the READER consults at the handoff. It
        # lives here rather than in `_handoff`'s signature so that a control
        # substituting that method with a three-argument stub still works.
        self._handoff_decide = None
        self._handoff_frame = None
        self._handoff_record = None
        # R-168-R4a. AUTHORITY STATE, BEHIND ITS OWN SHORT LOCK.
        #
        # A cancellation or a descriptor invalidation is an authority that must
        # still win while a reader is parked at the handoff. Round 3 put the
        # reader's CHECK inside the settlement lock and left the WRITERS
        # outside it, so the check just moved the window. Putting the writers
        # under the settlement lock instead was measured and is worse: the
        # reviewer's instrument pauses the reader INSIDE that lock and requires
        # a writer to complete during the pause, so a writer that needs the
        # same lock times out -- four of six rows failed with "action
        # incomplete" rather than with a wrong answer.
        #
        # So the writers never wait on a reader. They record and bump an EPOCH
        # here, atomically; the reader decides from recorded state, builds its
        # frame outside, and re-reads the epoch in the critical section that
        # discharges the record. A moved epoch means re-derive before
        # discharging. The decision that reaches the wire and the discharge are
        # atomic with respect to the recorded state, which is the ownership
        # that matters and the one a wire can prove.
        # REENTRANT, and the reason is the re-derivation below: the reader
        # holds this lock across the final decision so that no writer can land
        # between it and the discharge, and the decision it re-runs reads
        # authority through `cancellation_accepted` and `authority_state`,
        # which take this same lock. A plain Lock deadlocks the reader on
        # itself there; an RLock lets the owner re-enter and still blocks every
        # other thread, which is the exclusion the property needs.
        self._authority_lock = threading.RLock()
        self._cancelled_ids: set = set()
        self._invalidated_as = None
        # R-168-R5. The epoch, and the epoch A DECISION WAS DERIVED FROM.
        #
        # Round 4 claimed the decision and the discharge were atomic because
        # they are adjacent lines. They are not: the reader releases this lock
        # when the decision returns and takes the settlement owner only, which
        # the writers do not need. ASTRA's XD01 measured the window six ways --
        # a cancellation completing there still lost.
        #
        # ADJACENT LINES ARE NOT ATOMICITY. What closes the window is a stamp:
        # every authority READ records the epoch it saw, and the discharge
        # refuses to spend a decision derived from an older one. The stamp is
        # taken at the READ and not before the call, which is the difference
        # between this and the epoch round 3 proposed: a writer that lands
        # BEFORE the decision reads is already visible to it and needs no
        # re-derivation, so the re-derivation fires exactly when the decision
        # is actually stale.
        self._authority_epoch = 0
        self._authority_observed = None
        # RC17. identity -> the core key whose generation this record answers.
        self._settling_key: dict = {}
        # R-168-R6/F2. CLIENT IDS ADMITTED AND NOT YET ANSWERED ON THE WIRE.
        #
        # Kept HERE and not on the route because admission is the session's
        # event however the caller reached it -- the reviewer's controls admit
        # straight through this method -- and kept apart from every other table
        # because it has to OUTLIVE retirement. The release paths retire the
        # record and THEN fail to authorise, and at that moment `_pending`,
        # `_settling` and the core all agree there is nothing outstanding while
        # the client has received no bytes at all. Retirement is not answering;
        # a frame reaching the sink is.
        # R-168-R8/F2. BY IDENTITY, and round 6 held bare request ids. The
        # session's own tables key on `key(origin, request_id)` -- which
        # carries the JSON TYPE -- precisely because 1 and 1.0 are different
        # ids to a peer and the same key to Python: `{1, 1.0}` is `{1}`. Two
        # clients waiting, one recorded as owed, and the second never answered.
        # Third time in two days that I used a weaker key than the session's
        # own identity shape.
        # R-168-R9. TOKENS, not identities, and this is the FOURTH round of one
        # mistake. `_claimed[identity]` on #179, `_unanswered` by bare id here,
        # `settle_from` comparing one element of a token, and now these two.
        #
        # The rule is sharper than "always use the token", and the sharp form
        # is what stops the next one. A table describing the LIVE correlation
        # may be keyed by identity: admission refuses an id already pending or
        # settling, so only one generation is ever live and the identity cannot
        # be ambiguous -- `_pending`, `_settling`, `_generation` are right as
        # they are. A table whose entries OUTLIVE the correlation must carry
        # the generation, because its entries span generations by construction.
        #
        # These two outlive it on purpose: an obligation stands until a frame
        # reaches the sink, which is after retirement, and a finished answer is
        # remembered for ever. Keyed by identity, a COMPLETED generation spoke
        # for a live one -- it consumed the new obligation's take and, through
        # `_answered_final`, refused to let it be restored. Two admitted
        # requests, one response.
        self._unanswered: set = set()
        self._answered_final: set = set()
        # R-168-R9/(a). WHICH obligation the frame just yielded discharges.
        #
        # The consumer cannot work it out from the frame: an id can have two
        # unanswered tokens at once -- a finished generation whose frame never
        # reached the sink, and a live one -- and that ambiguity IS the defect.
        # So the reader, which owns `record_key`, says. Set under the owner
        # immediately before each yield and read by the consumer immediately
        # after it, on the one thread that does both; `pump_upstream` is a
        # `for` loop over this generator, so there is no window between them.
        self._yielded_obligation = None
        # identity -> the Cause this item settles with, when it is not CLEAN.
        self._settling_cause: dict = {}
        # R-CLOSE-KIND-R3/(1). THE CAUSE A LOCAL WRITER HAS COMMITTED TO, by
        # TOKEN, before a byte of its answer moves.
        #
        # `_to_client` can block inside the sink, and while a withhold was
        # paused there a legitimate close terminalised the item with ITS cause.
        # The withhold's own settlement then arrived at a core that had already
        # ended and left it alone, so the client held a frame saying
        # APPROVAL_REQUIRED while the receipt said MALFORMED_UPSTREAM: one item,
        # two accounts of how it ended, and nothing raised.
        #
        # Settling early instead is not the fix -- #179's row
        # `test_a_locally_claimed_answer_still_counts_against_the_bound` says an
        # answer mid-write must still count against the outstanding bound, and
        # settling releases the correlation. So the CAUSE is committed here
        # while the CORRELATION stays outstanding, and the close settles a
        # committed item with the cause its wire frame carries.
        #
        # BY TOKEN, because a claim outlives the correlation it describes: this
        # is a spanning table and `warroom/r168-followups/key_shape_audit.py`
        # governs it as one.
        self._committed_cause: dict = {}
        # T8.R6's second half, written by whoever owns the write queue.
        self.queued_bytes = 0
        # AR11, T8.R5. When each item was admitted, so the upstream-response
        # deadline has something to measure. A bound with no clock behind it is
        # a number in a table.
        self._admitted_at: dict = {}
        # AR10. One cell, written by the reader and read by the watchdog:
        # when an incomplete frame first appeared in the buffer, or None.
        self.partial_frame_since: list = [None]
        # R-179-R7. EVERY OUTSTANDING LOCAL CLAIM, BY ITS FULL ATTEMPT TOKEN.
        #
        # Round 6 keyed this by IDENTITY, which is the id-only key this PR has
        # spent six rounds removing -- introduced, of all places, in the fix
        # for the bound. Same-id reuse is reviewed behaviour, so two live
        # generations of one id can both be claimed, and a dict keyed by
        # identity kept only the newest: nine owed, one counted, a tenth
        # admitted. Finishing the newer one erased the older one's slot as
        # well, and the teardown retained one obligation for two.
        #
        # A record is keyed on WHAT IT RETIRES. These are tokens, counted per
        # origin per token, retired only by the matching token, and walked in
        # full by `_close`.
        self._claimed: set = set()
        # R-179-R7/(d). Core keys whose WIRE ANSWER somebody has committed to
        # delivering. The close walk and a running local writer both used to
        # assume it was theirs, so one request got two frames; whoever takes it
        # first under `_settlement` owns it and the other finds nothing to do.
        self._delivering: set = set()
        self._generation: dict = {}       # key -> how many times it has been issued
        self._closed: tuple | None = None

    # ── admission ───────────────────────────────────────────────────────────
    def admit_request(self, request_id, *, method, origin, on_refusal=None,
                      on_attempt=None):
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
                        "the client used the proxy's control id namespace",
                        kind="ID_NAMESPACE_CLAIMED")
            return False
        identity = key(origin, request_id)
        # R-179-R3/XE02. A NEW ATTEMPT OWNS ITS OWN REFUSAL STATE. Round 2 kept
        # the cause in a table keyed by identity and cleared it only on
        # success, so an id refused OVERLOADED and then refused again for a
        # different reason still answered the client OVERLOADED: the route
        # asked why, and was told why the PREVIOUS attempt failed. Clearing
        # here, before any decision, means `refusal_for` can only ever describe
        # the attempt the caller is holding.
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
                            "still being answered",
                            kind="ID_REUSED_WHILE_SETTLING")
            else:
                self._close("MALFORMED_UPSTREAM",
                            "upstream reused an id whose previous request is "
                            "still being answered",
                            kind="ID_REUSED_WHILE_SETTLING")
            return False
        if identity in self._tombstones:
            # A cancelled id is refused for the rest of the session. The request
            # it named is gone and a reply to it would be a reply to nothing.
            return False
        if identity in self._pending:
            if origin == ORIGIN_CLIENT:
                self._close("MALFORMED_CLIENT",
                            "the client reused an id that was already pending",
                            kind="ID_REUSED_WHILE_PENDING")
            else:
                self._close("MALFORMED_UPSTREAM",
                            "upstream reused an id that was already pending",
                            kind="ID_REUSED_WHILE_PENDING")
            return False
        # T6.R6 stores an id with its GENERATION. A cancelled id is tombstoned
        # for the session, but a COMPLETED one may legitimately be used again,
        # and without a generation the core refuses the second request because
        # it has already settled that identity. The generation is what makes
        # "the same id, a later request" a different item rather than a repeat.
        # RC20. The INSERT happens under the same lock as the test, re-checking
        # both tables, so nothing can move an entry between deciding and
        # recording.
        # R-179-R6/R5_UNKNOWN_LIVE. THE UNKNOWN-METHOD REFUSAL LIVES HERE, and
        # its position is the finding. It used to run FIRST, before the three
        # protocol tests above, and it reserves a generation -- the same
        # counter that names the LIVE correlation under this identity. So an
        # unknown method sent on an id whose real request was still pending
        # renamed that request's core key: the core went on owing the old key,
        # `_core_key` returned the new one, and the answer that finally arrived
        # settled a generation nobody owned while the original debt stayed owed
        # with no pending entry. Pending 0, owed 1, no exception, no timing
        # assumption -- ordinary frames in order.
        #
        # OWNERSHIP IS VALIDATED BEFORE ANYTHING IS RESERVED. Reusing a live,
        # settling or tombstoned id is a fact about the CORRELATION and it is
        # decided above, on its own terms: a duplicate now closes the session
        # coherently whatever method it carried, instead of being refused by a
        # path that quietly renames the request it collided with. Only an id
        # that owns nothing reaches this line, so the reservation here cannot
        # take anything away from anyone.
        #
        # The refusal still RESERVES (M13) and still travels with an attempt
        # identity (R4_UNKNOWN_TOKEN_1/2): those two rows are the reason this
        # block exists at all, and moving it does not weaken either.
        if origin == ORIGIN_CLIENT and not handshake.client_method_known(method):
            self._core._emit("ADMISSION_REFUSED", request_id,
                             reason="UNINSPECTED_METHOD", method_known=False)
            reserved = self._reserve(identity)
            _tell(on_refusal, Attempt(identity, reserved[-1],
                                      Cause("UNINSPECTED_METHOD", "S1")))
            return False
        # T801, T8.R6, ROUND 2. The bound is evaluated and the slot reserved
        # inside ONE critical section, and it runs HERE -- after every protocol
        # test above -- because the two are different kinds of answer.
        #
        # R-179-R2/DP01: malformed before resource. At capacity, a duplicate id
        # used to be refused OVERLOADED, so a client that broke the protocol was
        # told the server was busy and the session stayed open on a correlation
        # table both ends now disagree about. Protocol validation decides first;
        # only a well-formed request can be too many.
        #
        # R-179-R2/AR06: the check and the insert are ONE step. Round 1 read the
        # occupancy outside the lock, so two admissions both read seven and both
        # inserted: nine pending against a cap of eight, reachable with ordinary
        # concurrent traffic and no fault injection at all.
        with self._settlement:
            if identity in self._settling or identity in self._pending:
                return False
            breach = bounds.check_admission(
                outstanding=self._outstanding_locked(origin), queued=0)
            # R-179-R3/XR03. THE ATTEMPT'S GENERATION IS RESERVED HERE, in the
            # same critical section as the decision, whichever way the decision
            # goes. Round 2 reserved the refused attempt's generation in a
            # SECOND critical section inside `_refuse_overloaded`, after this
            # one had been released: pause a refusal between the two and an
            # ordinary admission of the same id can complete in the gap, and
            # the refusal's later bump then renamed the live item's key --
            # orphaning an entry the core still owed and raising out of the
            # reader. A generation handed out here can never be taken back,
            # so each attempt keeps exactly what it was given.
            self._generation[identity] = self._generation.get(identity, 0) + 1
            reserved = self._core_key(identity)
            if breach:
                refused_with = Attempt(identity, self._generation[identity],
                                       Cause(breach.reason, breach.rule))
            else:
                self._pending[identity] = method
                # MERGE, #168 r9 onto #179. These two writes were r9's and sat
                # here unconditionally. They belong INSIDE the else: an
                # obligation is owed for an ADMITTED request, and
                # `bounds.check_admission` is origin-independent, so a client at
                # the outstanding cap takes the breach branch below. Recorded
                # unconditionally, an overload-refused client request would owe a
                # wire answer for ever -- `_pending` is never set, the core never
                # admits it, no frame is ever generated for it, and `_unanswered`
                # outlives retirement by design, so nothing would discharge it.
                #
                # Keyed on the CARRIED `reserved`, not on a fresh
                # `_core_key(identity)`. Same tuple here, and it is the token this
                # entry belongs to rather than whatever "current" says later --
                # #179's own rule for anything that outlives its correlation.
                self._admitted_at[identity] = time.monotonic()
                if origin == ORIGIN_CLIENT:
                    self._unanswered.add(reserved)
        if breach:
            # OUTSIDE the lock: the settlement below takes the core's lock, and
            # taking the core's under ours is the nesting the reader avoids.
            # Everything it needs was decided above; it only reports.
            self._refuse_overloaded(reserved, request_id, method, origin, breach)
            _tell(on_refusal, refused_with)
            return False
        if on_attempt is not None:
            # The ADMITTED attempt's own token, handed over at the only moment
            # it is unambiguous: now. A caller that re-reads the generation
            # later is back to the id-only key, which is the whole of this
            # round.
            on_attempt(Attempt(identity, reserved[-1]))
        self._core.admit(reserved, method=method, origin=origin)
        if self._closed:
            # RC06. The session closed while this admission was in flight, so
            # the item was admitted into a table that has already been torn
            # down and nothing will ever settle it. Reporting success would
            # hand the caller a request the session has no intention of
            # answering.
            self._pending.pop(identity, None)
            return False
        return True


    def sweep_deadlines(self, *, partial_since=None, now=None):
        """AR10 and AR11, T8.R3 and T8.R5. The deadlines, actually applied.

        `bounds.check_deadline` has held these numbers since the slice that
        wrote it and nothing asked it anything, so a server could hold a
        request for ever or stop halfway through a frame and the session would
        wait as long as the server liked. A mediator that can be made to wait
        indefinitely is a mediator that can be removed from the path by doing
        nothing.

        Called from a watchdog rather than from the reader, because the reader
        is BLOCKED in exactly the cases that matter. Returns the breach it
        closed on, or None.

        `partial_since` is when the reader last had an incomplete frame in its
        buffer, or None when it does not. That is the frame-assembly clock, and
        only the reader can know it.
        """
        if self._closed:
            return None
        now = time.monotonic() if now is None else now

        partial_since = (self.partial_frame_since[0] if partial_since is None
                         else partial_since)
        if partial_since is not None:
            breach = bounds.check_deadline(
                "frame_assembly", elapsed_ms=(now - partial_since) * 1000)
            if breach:
                self._close(breach.reason, breach.detail, rule=breach.rule)
                return breach

        for identity, admitted in list(self._admitted_at.items()):
            if identity not in self._pending or identity[0] != ORIGIN_CLIENT:
                continue
            breach = bounds.check_deadline(
                "upstream_response", elapsed_ms=(now - admitted) * 1000)
            if breach:
                self._close(breach.reason, breach.detail, rule=breach.rule)
                return breach
        return None
    def _reserve(self, identity):
        """Burn a generation for THIS attempt and return its core key.

        Every admission decision calls this, refusals included. Round 4
        reserved for the bound refusal and not for the unknown-method one, so
        that refusal reached the route with no attempt identity at all --
        the structural hole ASTRA's R4_UNKNOWN_TOKEN rows name.
        """
        with self._settlement:
            self._generation[identity] = self._generation.get(identity, 0) + 1
            return self._core_key(identity)

    def _outstanding_locked(self, origin):
        """Outstanding correlations for ONE origin. Call under `_settlement`.

        R-179-R2/AR05: the union of PENDING and STILL-HELD. An item being
        answered has left `_pending` and sits in `_settling` while the handoff
        completes, and it is still outstanding for every purpose this bound
        exists to serve -- the client is still waiting for it and its id is
        still ours. Counting `_pending` alone admitted a ninth correlation
        during any real response, which is not a rare window: it is every
        response the proxy ever delivers.

        R-179-R2/AR04, by refinement rather than exemption. The contract row
        names outstanding correlations with no origin qualifier, and a literal
        reading (one shared count of eight) lets a chatty server close the
        client's window -- one upstream request outstanding permanently costs
        the client a slot. Counting only the client left upstream UNBOUNDED,
        which is worse. So each origin is bounded separately at the same
        figure: no origin is unbounded, and neither can spend the other's
        window. The contract copy carries this as the T8.R6 origin scope note
        (v5.2) with this reason; it is a narrowing of the row, and ASTRA's AR04
        as written measures the literal reading it replaces.
        """
        # R-179-R6/R5_LOCAL_CAP adds the third table. An attempt claimed for a
        # LOCAL answer has left `_pending` before its frame is written, and
        # between the claim and the settlement it was counted by nothing: eight
        # of them parked at their writers left the count at zero and a ninth
        # request was admitted with nine debts owed. T8.R6 names in-flight held
        # messages, and a held message being answered is the most in-flight it
        # ever gets.
        return (sum(1 for i in self._pending if i[0] == origin)
                + sum(1 for i in self._settling if i[0] == origin)
                + sum(1 for t in self._claimed if t[0] == origin))

    def _refuse_overloaded(self, reserved, request_id, method, origin, breach):
        """T6.R7 + T4.R7. A refusal that a receipt can be graded against.

        R-179-R3: this method only REPORTS. The decision, the slot and the
        generation were all settled inside the critical section above, so a
        caller that pauses here -- as ASTRA's XR03 does -- cannot race an
        ordinary admission of the same id, because there is nothing left here
        for the two to disagree about.

        R-179-R2/AR07: round 1 answered `False` and emitted ADMISSION_REFUSED,
        and that was the whole of it -- no terminal settlement, so nothing in
        the receipt stream said the item ENDED and the caller had to invent a
        reason for the client. (`route.py` invented UNINSPECTED_METHOD, which
        told a client that had done nothing wrong that its method was not
        inspectable.) The item is admitted and settled S3/OVERLOADED here, so
        there is exactly one terminal receipt for it and the route layer reads
        the cause instead of assuming one.

        The generation reserved for the refused attempt is its own, so its core
        key can never be confused with a later, legitimate use of the same id.
        """
        # R-179-R3, my own audit finding: `detail` is PROSE and prose does not
        # belong in evidence. It is the field `Cause.as_receipt` excludes by
        # name, for a reason recorded there -- the frame receipt leaked peer
        # material through exactly this field twice. WHICH BOUND BROKE is a
        # fixed vocabulary, and it is what a reader actually needs.
        self._core._emit("ADMISSION_REFUSED", request_id,
                         reason=breach.reason, bound=breach.bound,
                         origin=origin)
        self._core.admit(reserved, method=method, origin=origin)
        self._core.settle(reserved, Cause(breach.reason, breach.rule),
                          origin=origin)

    def _core_key(self, identity):
        return identity + (self._generation.get(identity, 0),)

    def expects(self, request_id, *, origin):
        return key(origin, request_id) in self._pending

    def accept_cancellation(self, request_id, *, origin):
        """Record a cancellation as AUTHORITATIVE, and never wait on a reader.

        The writer takes ITS OWN lock and never the reader's, which is what
        lets a cancellation complete while a reader is parked at the handoff --
        the thing the reviewer's XB03 requires and the thing a writer under the
        settlement lock cannot do.
        """
        with self._authority_lock:
            self._cancelled_ids.add(key(origin, request_id))
            self._authority_epoch += 1

    def accept_invalidation(self, reason):
        """T5.R4. The descriptors moved; every undelivered answer of this
        generation is from a server nobody approved."""
        with self._authority_lock:
            self._invalidated_as = reason
            self._authority_epoch += 1

    def cancellation_accepted(self, request_id, *, origin):
        """Is THIS id's cancellation accepted? Asked with the session's own key.

        The first wiring of this compared the route's `_typed(id)` against the
        identities stored here, which are `key(origin, id)` triples: the shapes
        never matched, so every lookup said no and two of my own rows went red
        with the original crossing. Comparing keys is the session's job because
        the key is the session's shape.
        """
        with self._authority_lock:
            self._observe_authority()
            return key(origin, request_id) in self._cancelled_ids

    def authority_state(self):
        """The cancelled ids and the invalidation, read TOGETHER under one lock.

        Read separately a caller could take one that is newer than the other,
        which is the same class of bug as the one this round is about, one
        level down.

        THE EPOCH IS BACK, AND THIS DOCSTRING IS WHY. Round 4 said here that
        there was no window to validate, because the decision is taken inside
        the settlement owner on the line before the discharge and "nothing can
        move between them". That is false and it was measured: this lock is
        released when this call returns, the writers never take `_settlement`,
        and ASTRA's XD01 completed a cancellation in that window six times --
        the reader delivered the original every time. I argued the epoch out of
        round 4 on that sentence, so the sentence is kept above its correction:
        ADJACENT LINES ARE NOT ATOMICITY, and an argument is not a measurement.

        The read STAMPS the epoch it saw (`_observe_authority`), and the
        discharge refuses to spend a decision derived from an older one.
        """
        with self._authority_lock:
            self._observe_authority()
            return frozenset(self._cancelled_ids), self._invalidated_as

    def _observe_authority(self):
        """Record the epoch THIS decision was derived from. Under the lock.

        The EARLIEST read wins, because a decision that read the cancelled set
        at one epoch and the invalidation at a later one is internally
        inconsistent and has to be re-derived just as surely as a stale one.
        `None` means no authority was read at all -- the gate returned on a
        recorded fault or on a missing id -- and a decision that never asked
        cannot have asked too early.
        """
        if self._authority_observed is None or \
                self._authority_epoch < self._authority_observed:
            self._authority_observed = self._authority_epoch

    def release_decision(self, request_id, *, origin=ORIGIN_CLIENT):
        """May this crossing go as it is, or what replaces it. THE one answer.

        R-168-R6/F1. The policy moved here because every input it reads is
        already the session's: the recorded terminal cause, the cancelled set,
        the invalidation and the epoch that dates all three. `Route._release_gate`
        keeps its name and its signature -- reviewer controls wrap that
        attribute and count its calls -- and is now the adapter that calls this.
        One implementation, two entry points, and not a copy: the retirement
        below re-derives through THIS, so it can take a fresh decision without
        spending a gate call that XE02_rederive_writer counts.

        Precedence, unchanged and asserted by XB04: a recorded S3 fault is
        terminal and no authority overrides it; then cancellation; then the
        invalidation. `None` lets the crossing through.
        """
        identity = key(origin, request_id)
        with self._authority_lock:
            self._observe_authority()
            recorded = self.recorded_terminal(request_id, origin=origin)
            if recorded is not None and recorded.rule == "S3":
                return None
            if identity in self._cancelled_ids:
                return "REQUEST_CANCELLED"
            if self._invalidated_as:
                return "DESCRIPTOR_CHANGED"
            return None

    def _final_decision(self, request_id, decided):
        """The decision that actually reaches the wire, taken UNDER the lock.

        Called from inside the settlement owner, at the discharge. If authority
        moved after the decision read it, the decision is re-derived HERE,
        while this lock is held, so nothing can move between the re-derivation
        and the discharge that follows it. That is the shared ordering round 4
        claimed from adjacency and did not have.

        The callback is re-entered at most ONCE, and only when the epoch says
        it must be: the reviewer's XG01 counts the calls, and a control that
        drives its writer INTO the decision is already accounted for by the
        stamp -- that decision read the new epoch and is not stale.
        """
        with self._authority_lock:
            observed = self._authority_observed
            if observed is None or observed == self._authority_epoch:
                return decided
            # Stale: an authority landed between the read and this point, and
            # on this head that is the whole of XD01. Re-derive through the
            # SAME callback, so the recorded-fault precedence and the reason
            # mapping stay in one place rather than being restated here.
            if self._handoff_decide is None:
                return decided
            return self._handoff_decide(request_id)

    def recorded_terminal(self, request_id, *, origin):
        """The cause this item is ALREADY settled with, or None.

        R-168-R4a/XB04. T4.R4 Rule A: an earlier independent S3 fault is
        terminal. Rule B lets a hold beat a NORMAL completion, not a recorded
        fault. A worker that returned an invalid completion settles
        SCAN_EXCEPTION before the handoff, and a cancellation arriving after
        that must not overwrite it -- the client would be told its request was
        cancelled while the receipt says the scan faulted, and the two answers
        disagree about what happened.

        Read from the RECORD, not from the route's flags, which is the half
        round 3 was missing: the gate saw only the id.
        """
        identity = key(origin, request_id)
        record_key = self._settling_key.get(identity) or self._core_key(identity)
        return self._core.settled_as(record_key)

    def is_settling(self, request_id, *, origin):
        """The item has left `_pending` and its answer has NOT yet crossed.

        R-168-R3. `expects` reads one table, and a caller asking "is this still
        ours?" during a handoff got False -- so a cancellation arriving in that
        window was treated as though the client had already been answered. It
        had not been: the frame is still in the reader's hands.
        """
        return key(origin, request_id) in self._settling

    def expected_method(self, request_id, *, origin):
        return self._pending.get(key(origin, request_id))

    # ── responses ───────────────────────────────────────────────────────────
    def deliver_response(self, *, origin, request_id, frame=None,
                         defer_retire=False, inspect=None, raw=None):
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
                        "a response arrived for an id that is not pending",
                        kind="RESPONSE_NOT_PENDING")
            return None

        if frame is not None and not self._shape_matches(identity, frame):
            self._close("MALFORMED_UPSTREAM",
                        "the response shape does not match the request it "
                        "claims to answer",
                        kind="RESPONSE_SHAPE_MISMATCH")
            return None

        # T802, T8.R2. The content bound existed in the table and nothing
        # applied it, so a 262,145 byte result was forwarded to the model
        # intact. An over-budget FRAME already closes the session here; content
        # is the same row's other half and is treated the same way, so the
        # bound cannot be walked around by putting the bytes one level further
        # in.
        if frame is not None and "result" in frame:
            over = bounds.check_content(selector.content_bytes(frame["result"]))
            if over:
                self._close(over.reason, over.detail, rule=over.rule,
                            budget=over.budget)
                return None

        # THE INSPECTION HAPPENS HERE, and the position is the whole repair.
        #
        # AFTER the shape check and the content bound, so a malformed result is
        # a protocol fault before anybody inspects it -- it was answered as a
        # finding with the session left open, which also meant the shape check
        # could be skipped by attaching a finding.
        #
        # BEFORE the item moves from `_pending` into `_settling`, because the
        # inspection needs to know which METHOD the result answers and that
        # lives in the pending table. Reading it a few lines lower finds
        # nothing and silently inspects nothing, which is how the first version
        # of this repair passed two rows and stopped scanning.
        #
        # What the seam returns then settles through the SAME call and hands
        # off through the SAME lock as the original would have, so the close,
        # the cancel and the one-answer-per-id rule apply to a replacement
        # exactly as they apply to an original.
        verdict = inspect(raw, frame) if inspect is not None else None
        cause = replacement = None
        if verdict is not None:
            replacement, reason, rule = verdict
            cause = Cause(reason, rule)

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
        if cause is not None:
            self._settling_cause[identity] = cause
        if not self._settle_outside_lock(identity):
            return None
        if verdict is not None:
            return _Replaced(replacement)

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

    def commit_local_cause(self, token, reason, rule):
        """R-CLOSE-KIND-R3/(1). Say how this answer ends BEFORE it is written.

        The receipt has to agree with the wire, and the wire is committed the
        moment the bytes leave. A close that wins the race mid-write must
        therefore settle this item with the cause the client was told, not with
        its own: the close is why the session is ending, it is not a second
        opinion about how this one request ended.
        """
        with self._settlement:
            self._committed_cause[token] = (reason, rule)

    def claim_for_local_answer(self, token):
        """This attempt is being answered HERE; upstream can no longer answer it.

        R-179-R5/(3). A withheld request is never forwarded, so a response
        carrying its id is unsolicited by construction. Round 4 left the item
        in `_pending` until the withhold's trailing settlement, which is after
        the client frame is written -- so in the window between the two, a
        response ARRIVED AND WAS ACCEPTED for a request upstream had never
        seen. ASTRA built his R4_WITHHOLD_OWNER on exactly that step.

        Claiming it first closes the window: the item leaves `_pending` before
        the answer is written, and `deliver_response` then reads the id the way
        it should have read it all along -- as one nobody is waiting on.

        Returns False when the token is stale, so a caller that no longer owns
        this id does not quietly claim a newer attempt's item.
        """
        identity = token[:-1]
        with self._settlement:
            if self._generation.get(identity) != token[-1]:
                return False
            if identity not in self._pending:
                return False
            self._pending.pop(identity)
            self._answered.add(identity)
            # R-179-R6/R5_LOCAL_CAP. STILL COUNTED, AND THIS LINE IS THE FIX.
            # Round 5 dropped the item out of `_pending` and into nothing that
            # `_outstanding_locked` reads, so eight attempts refused by the
            # ordinary approval path and parked at their writers counted ZERO
            # against a bound of eight, and a ninth request was admitted with
            # nine debts owed. That is a regression of the bound itself --
            # round 4 refused that ninth in the same window -- and T8.R6 names
            # in-flight held messages and obligations mid-handoff explicitly.
            #
            # ITS OWN TABLE, and `_settling` was measured first. Putting the
            # item there counts it, and it also makes admission treat the id as
            # "still being answered" and CLOSE the session on reuse -- which
            # turned the reachable R4_WITHHOLD_OWNER row red, because the
            # newer attempt it admits on that id stopped being admissible at
            # all. That is a redesign of reviewed behaviour smuggled in under a
            # bound fix, so it was backed out.
            #
            # `_claimed` is counted by `_outstanding_locked` and drained by
            # `_close`, and it is read by nothing else: admission still decides
            # reuse on `_pending`/`_settling` exactly as before, and
            # `deliver_response` still reads this id as one nobody is waiting
            # on, so the unsolicited-response window this method exists to
            # close stays closed.
            self._claimed.add(token)
            return True

    def take_delivery(self, token):
        """Claim the WIRE ANSWER for this item. True to the first caller only.

        R-179-R7/(d). Atomic core settlement establishes one TERMINAL; it
        cannot establish one FRAME. A local writer paused inside the client
        sink and a close walking its retained obligations were both certain
        they owed the client an answer, and the client got both. Ownership of
        delivery is decided here, under the settlement owner, exactly once.
        """
        with self._settlement:
            return self._take_delivery(token)

    def _take_delivery(self, token):
        """Call under `_settlement`. THE single acquire, over BOTH sets.

        R-168-R12/(a), ASTRA LC01 + LC03. Delivery and the obligation used to be
        separate sets, so a writer could own one and look unowned to whatever
        asked about the other. The teardown asks here, saw the successful list
        as nobody's, and retained a second response for a request already
        answered -- one answer for the first request and TWO for the second, on
        a real pipe, 3 of 3 crossings. Two sets meant two answers.

        Both public entry points land here, so a taker of either is the owner of
        both. `take_delivery` keeps its name and its meaning because reviewer
        controls hook that attribute to drive the race; the plumbing gives way,
        not the control.
        """
        if token in self._delivering:
            return False
        self._delivering.add(token)
        self._unanswered.discard(token)
        return True

    def settle_attempt(self, token, reason, rule):
        """Settle the item THIS attempt owns, or refuse in a way the caller can
        read.

        R-179-R5/(2). `settle_from` recomputed the CURRENT generation, so an
        older withheld attempt, resuming after a newer one had been admitted on
        the same id, popped the newer entry and settled its generation -- the
        new request lost its debt. Settling by the owned token cannot do that:
        if the generation this caller owns is no longer the live one, the item
        it is talking about is gone and there is nothing here to settle.

        Returns the terminal cause on success, or None when the attempt is
        stale. None is a REFUSAL and not a silent no-op: the caller wrote a
        frame for an item it no longer owns, and it needs to know that.
        """
        self._committed_cause.pop(token, None)
        identity = token[:-1]
        with self._settlement:
            # POP ONLY WHAT THIS ATTEMPT OWNS. `_pending` is keyed by identity
            # with no generation in it, so popping blind is the id-only key
            # again: if a newer attempt has been admitted on this id, that
            # entry is ITS debt and taking it is precisely the defect
            # (R4_WITHHOLD_OWNER).
            #
            # A stale token still settles its OWN core item. The first draft of
            # this refused outright when the generation had moved, which reads
            # as the safer choice and is not: the older attempt's core entry
            # was admitted and never answered, so refusing leaves it owed for
            # the life of the session. Measured before it was changed.
            mine = self._generation.get(identity) == token[-1]
            if mine:
                self._pending.pop(identity, None)
                self._answered.add(identity)
            # THE ANSWER OBLIGATION ENDS HERE, so the count this attempt has
            # been holding since `claim_for_local_answer` is released here --
            # by the OWNED token and never blind, because `_settling` is keyed
            # by identity and a newer attempt's entry is ITS debt (the same
            # rule as the pop above).
            # BY THE MATCHING TOKEN, so another generation's live claim on
            # this same id keeps its own slot.
            self._claimed.discard(token)
        # R-179-R6/R5_WITHHOLD_CLOSE. ONE CORE CALL, under the core's lock,
        # returning WHICH happened. Round 5 asked `settled_as` and then called
        # `settle`, and a legitimate `_close` landing between the two settled
        # the token first, so the `settle` raised `Settled` out of
        # `Route.client_frame` -- an exception reaching a client where a
        # receipt belongs. The guard was right and its shape was not: two
        # acquisitions of a lock are not one critical section.
        terminal, already = self._core.settle_or_report(
            token, Cause(reason, rule), origin=identity[0])
        if already:
            self._core._emit("SETTLEMENT_REFUSED", identity[2],
                             reason="already_settled", offered=reason,
                             origin=identity[0])
            return None
        return terminal

    def settle_from(self, origin, request_id, reason, rule, *, token=None):
        """T6.R3. An upstream REQUEST is answered in U's id namespace, never C's.

        R-179-R5, the class fix rather than the instance. This recomputed
        `_core_key(identity)` AFTER popping, which is the current generation by
        definition -- the same id-only key that cost rounds 2 and 4. A caller
        that owns an attempt passes its token and settles exactly that; a
        caller that does not gets the generation observed HERE, captured under
        the same lock as the pop so nothing can move between the two.

        A token that is no longer the live generation is a TYPED REFUSAL and
        not a silent no-op: the caller is talking about an item that is gone,
        and it needs to know rather than to have settled something else.

        R-179-R8. THE WHOLE TOKEN, and this method is where the round-7 rule
        stopped one API short. `cancel` learned it; this did not, and the two
        are the only entry points that take a token AND a separate identity --
        everything else here (`claim_for_local_answer`, `settle_attempt`,
        `take_delivery`) derives the identity FROM the token, so no
        disagreement between the two is possible there.
        
        Comparing only the generation let a REAL token for another item pass:
        a different id, the same numeric value with a different JSON type, or
        the same id from the other origin. The pending entry named by
        `request_id` was popped and the TOKEN's item was settled -- two items
        damaged by one call, and the ordinary response for the first then
        reached a second core settlement and raised out of the reader.
        """
        identity = key(origin, request_id)
        with self._settlement:
            # A token for ANOTHER ITEM touches neither: not this correlation,
            # which the caller asked about and does not own, and not the
            # token's own item, which the caller did not ask about.
            if token is not None and token[:-1] != identity:
                self._core._emit("SETTLEMENT_REFUSED", request_id,
                                 reason="wrong_item", offered=reason,
                                 origin=origin)
                return None
            if token is not None and self._generation.get(identity) != token[-1]:
                self._core._emit("SETTLEMENT_REFUSED", request_id,
                                 reason="stale_attempt", offered=reason,
                                 origin=origin)
                return None
            if identity not in self._pending:
                return None
            # OBSERVED, not recomputed later: captured with the pop.
            observed = token if token is not None else self._core_key(identity)
            self._pending.pop(identity)
            self._answered.add(identity)
        return self._core.settle(observed, Cause(reason, rule))

    def cancel(self, request_id, *, origin, token=None):
        """T6.R5 and T6.R6. The id is retired and tombstoned for the session."""
        identity = key(origin, request_id)
        # R-179-R5. THE GENERATION THIS CANCELLATION OBSERVED, captured with
        # the pop and under the lock. Reading `_core_key` at the settle below
        # was "current by definition", so a cancellation could settle a
        # generation admitted after it was accepted -- the same class as the
        # withheld attempt settling a newer debt, in the cancellation path.
        with self._settlement:
            # R-179-R6/R5_STALE_CANCEL. VALIDATED BEFORE THE POP, because the
            # pop and the tombstone are the irreversible part. Round 5 popped
            # first and validated never: a cancellation carrying the token of
            # an attempt that had already been answered retired the LIVE entry
            # admitted on that id afterwards, and tombstoned the id for the
            # rest of the session. The newer request kept its debt and lost its
            # pending correlation -- the same orphan this lane keeps producing,
            # reached through the new optional argument.
            #
            # A stale token cancels NOTHING. It does not pop, it does not
            # tombstone, and it never settles the generation it does not own;
            # it settles its own item if that is somehow still owed, which is
            # the identical rule `settle_attempt` follows.
            # R-179-R7/(b). THE WHOLE TOKEN, and round 6 compared its last
            # element. A token is (origin, id-type, id, generation): comparing
            # only the generation makes ANOTHER id's real token at the same
            # generation pass this check, so cancelling id 2 while holding id
            # 1's token popped id 2's correlation, tombstoned id 2, and settled
            # id 1. Generation equality is not ownership; the identity half is
            # most of the identity.
            # TWO DIFFERENT WRONGS, and round 7's first draft collapsed them.
            # A token for ANOTHER id is not this caller's business at all, so
            # it changes NOTHING -- it must not settle the item it names either,
            # because the caller asked to cancel something else entirely. A
            # token for THIS id at an older generation is a late cancellation
            # of an attempt that has been answered: it cancels nothing, and it
            # may still settle its own item if that is somehow still owed,
            # which is R5_STALE_CANCEL's shape and `settle_attempt`'s rule.
            wrong_item = token is not None and token[:-1] != identity
            stale = token is not None and (
                wrong_item or token[-1] != self._generation.get(identity))
            observed = token if token is not None else self._core_key(identity)
            if not stale:
                self._pending.pop(identity, None)
        if stale:
            self._core._emit("SETTLEMENT_REFUSED", request_id,
                             reason="wrong_item" if wrong_item
                             else "stale_attempt",
                             offered="REQUEST_CANCELLED", origin=origin)
            if not wrong_item:
                self._core.settle_or_report(observed,
                                            Cause("REQUEST_CANCELLED", "S6"),
                                            origin=origin)
            return identity
        self._remember_tombstone(identity)
        if self._closed:
            # The tombstone table overflowed and the session closed inside this
            # call. The item is already settled by the teardown, and settling it
            # again would raise `Settled` out of an ordinary cancellation.
            return identity
        # One core call, for the reason recorded on `settle_attempt`: asking
        # and then acting is two acquisitions of the core's lock, and a
        # teardown between them turns an ordinary cancellation into a raise.
        self._core.settle_or_report(observed, Cause("REQUEST_CANCELLED", "S6"),
                                    origin=origin)
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
                        kind="TOMBSTONE_TABLE_FULL",
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
        # T803. Recorded BEFORE the early return. A clean exit with a non-zero
        # code is the case this is for, and it is precisely the case the early
        # return used to skip.
        self._core.record_upstream_exit(getattr(handle, "returncode", None))
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
                    "the upstream process exited with calls still pending",
                    kind="UPSTREAM_EXIT_WITH_PENDING")

    # ── reading ─────────────────────────────────────────────────────────────
    def read_upstream(self, stream, inspect=None, gate=None):
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
        # The gate is the caller's, for the length of this read. Stored
        # rather than threaded through the yield, and read under the
        # settlement lock at the handoff.
        # `gate` is (decide, build_frame) or None. Two callables rather
        # than one because they run on opposite sides of the settlement
        # lock, which is the whole of R-168-R4a.
        # R-168-R7. THREE callables now, and a 2-tuple still works: the build
        # is pure and repeatable, the RECORD is fallible and happens once. A
        # caller that passes two gets no recorder and behaves as before, which
        # keeps every control that builds its own gate tuple running.
        decide, frame, record = (tuple(gate) + (None,) * 3)[:3] if gate \
            else (None, None, None)
        self._handoff_decide, self._handoff_frame = decide, frame
        self._handoff_record = record
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

        # AR10. The reader publishes its frame-assembly clock so a watchdog can
        # read it while this loop is blocked, which is the only moment the
        # deadline matters.
        for raw in framing.bounded_lines(_as_reader(stream),
                                         framing.MAX_FRAME_BYTES,
                                         partial=self.partial_frame_since):
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
                            "the last frame ended without its terminator",
                            kind="FRAME_UNTERMINATED")
                yield from self._drain_refusals()
                return
            parsed = framing.parse_frame(raw, origin=ORIGIN_UPSTREAM)
            if not parsed:
                # The BUDGET travels with the cause. T8's rows name which bound
                # broke, and an answer that says OVER_BUDGET without saying
                # which one cannot be graded against a fixture.
                self._close(parsed.reason, parsed.detail, rule=parsed.rule,
                            budget=parsed.budget, kind=parsed.kind)
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
                # R-CLOSE-KIND-R3/(2). AN INVALIDATED SESSION FORWARDS NOTHING,
                # AND A NOTIFICATION IS NOT AN EXCEPTION.
                #
                # Invalidation means the descriptors moved, so every frame of
                # this generation is now something a server nobody approved has
                # said. Responses are covered -- they have an id, so the record
                # gate reaches them -- and a notification has no id, so it went
                # out regardless: the one frame shape that could still cross
                # after we had decided nothing may. Measured on bb7607b,
                # 07c5c67 and cf294f5 before it was written down; all three
                # forwarded it.
                #
                # Dropped with a receipt and NEVER a response, because a
                # notification has no id to answer in, and the receipt carries
                # WHICH invalidation stopped it -- a drop that cannot say why
                # is indistinguishable from a frame we simply lost.
                if self._invalidated_as:
                    self._core._emit("NOTIFICATION_DROPPED", None,
                                     supported=True,
                                     invalidated_as=self._invalidated_as)
                    continue
                verdict = inspect(raw, message) if inspect is not None else None
                if verdict is not None:
                    # T2.R12. Dropped with a receipt and never a response,
                    # because a notification has no id to answer in.
                    self._core._emit("NOTIFICATION_DROPPED", None,
                                     supported=True)
                    continue
                # T7.R2, RC28. ONCE THE CLOSE HAS WON, NOTHING CROSSES, AND A
                # NOTIFICATION IS NOT AN EXCEPTION. It carries no id, so the
                # record gate that gives responses their boundary does not
                # cover it, and this line delivered regardless: a close could
                # complete while the reader was parked here and the frame went
                # out anyway.
                #
                # The same shape RC18 settled for responses, for the same
                # reason: the decision rides the YIELD EXPRESSION, so it is
                # made when the line RUNS. A statement before the yield decides
                # too early and a close arriving in between still crosses.
                self._yielded_obligation = None
                yield self._handoff_notification(raw)
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
                self._yielded_obligation = init_key
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
                                           frame=message, defer_retire=True,
                                           inspect=inspect, raw=raw)
            if answer is None:
                yield from self._drain_refusals()
                return
            # ONE DELIVERY SITE, still. The seam's replacement crosses through
            # the SAME yield as an original, which is not tidiness: RC18 puts
            # the handoff decision IN the yield expression, and the vendored
            # controls locate that decision by finding exactly one yield in
            # this loop. A second one makes the instrument ambiguous and four
            # reviewed rows fail on the instrument rather than on behaviour.
            crossing = raw
            if isinstance(answer, _Replaced):
                if answer.frame is None:
                    # Settled with nothing to deliver; the obligation still ends.
                    self._retire_record(identity)
                    continue
                crossing = answer.frame
            # RC18/RC19/RC19b. The obligation ends HERE, under the lock, and
            # the yield happens only if this call says the close did not win.
            # The decision is IN the expression, so it is made when this line
            # runs rather than before it. None means the close won and nothing
            # crosses; consumers skip it.
            self._yielded_obligation = record_key
            yield self._handoff(identity, crossing, record_key)
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
                        "upstream exited with calls still pending",
                        kind="UPSTREAM_EXIT_WITH_PENDING")
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
                        "the initialize result is not a result object",
                        kind="INITIALIZE_RESULT_SHAPE")
            return None
        negotiated = handshake.negotiate(result)
        if not negotiated.ok:
            self._close(negotiated.reason,
                        "the server offered a protocol version outside the "
                        "frozen set",
                        rule="S3", kind=negotiated.kind)
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
        # T410. The same single constructor. A refusal going UP the pipe is
        # the same wire object as one going down, and a second way of building
        # it is a second set of rules to keep in step.
        body = envelope.withheld(
            request_id=request_id, reason_code=reason, rule=rule,
            accepted=False, status="not_run", inspection_complete=False,
            inspected_utf8_bytes=0, observed_content_bytes=0, elapsed_ms=0,
            rule_ids=(), catalog=frozenset())
        try:
            stdin.write((_json.dumps(body, separators=(",", ":"))
                         + "\n").encode("utf-8"))
            stdin.flush()
        except (OSError, ValueError):
            self._core._emit("UPSTREAM_REQUEST_REFUSED", request_id,
                             reason="write_failed")

    def _client_refusal(self, identity, reason, rule):
        """One JSON-RPC error to the client, in the id it used.

        T410. Built by `envelope.withheld` and by nothing else. This used to
        assemble its own `{reason_code, rule}` beside the envelope module,
        which is the exact failure that module was written to prevent: every
        rule it enforces -- the frozen reason catalog, the frozen statuses, the
        catalog-only bounded rule_ids, `**ignored` swallowing a caller's detail
        string -- applied to the construction that was NOT on the wire, and the
        one that was answered to nothing.

        The counters are zero and the status is `not_run` because that is what
        is true: a fault the pump found is a fault found BEFORE any scan, so no
        bytes were inspected. Saying so is what makes the refusal comparable to
        a fixture; a refusal that cannot state whether anything was looked at
        cannot be graded at all.
        """
        import json as _json

        request_id = identity[2]
        # The budget is LOOKED UP rather than passed in. It belongs to the
        # cause recorded for this item, and threading it through the signature
        # broke every reviewer subclass that wraps this method with the three
        # arguments the row names -- seventeen of ASTRA's v6 controls at once,
        # on a TypeError, before a single assertion ran. The shape of a refusal
        # is this method's business; who is waiting for it is the table's.
        budget = self._budget_for.get(identity)
        body = envelope.withheld(
            request_id=request_id, reason_code=reason, rule=rule,
            accepted=False, status="not_run", inspection_complete=False,
            inspected_utf8_bytes=0, observed_content_bytes=0, elapsed_ms=0,
            rule_ids=(), catalog=frozenset(), budget=budget)
        return (_json.dumps(body, separators=(",", ":")) + "\n").encode()

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
            # RD03/RD04/RD07/RD08. The cause is a PARAMETER because the result
            # direction settles some items as refusals, and it has to do that
            # through this path rather than beside it. A seam that settled on
            # its own skipped the ownership this function completes, and the
            # close, the cancel and the second-answer rule all hang off that.
            # RD03/RD04/RD07/RD08. The cause travels WITH the record, the way
            # `_settling_key` does, rather than as a parameter: the result
            # direction settles some items as refusals and has to do it through
            # this path, and every control that wraps this method takes the one
            # argument it has always taken.
            self._core.settle(core_key,
                              self._settling_cause.pop(identity, None)
                              or Cause("CLEAN", "S1"))
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
                # recorded is this client's one answer. `b""` and not None: a
                # consumer writes what the reader yields, and on a byte stream
                # zero bytes IS nothing -- it needs no special case.
                return b""
            standing = self._settling_key.get(identity)
            mismatch = standing is not None and standing != record_key
            # R-168-R4a. THE DECISION IS TAKEN HERE, INSIDE THE OWNER, AFTER
            # the line above and immediately before the discharge, and it is a
            # DECISION ONLY -- a reason or nothing. Three constraints meet at
            # this point and only this shape satisfies all three.
            #
            # A close racing the handoff must be BLOCKED by the owner while
            # this runs (XC01 measures exactly that, `not done.wait(.03)`), so
            # the decision cannot move outside the lock.
            #
            # A cancellation or invalidation completing while a reader is
            # parked at the line above must still win (XB03), so the WRITERS
            # cannot need this lock: they record under their own and this read
            # sees it because it happens after the pause, not before.
            #
            # And nothing here may write a receipt, because a failed write
            # answers by calling `_close`, which takes this same non-reentrant
            # lock (XB06 deadlocked on exactly that). So the FRAME is built
            # below, outside, from a decision already taken.
            self._authority_observed = None
            withheld = (self._handoff_decide(identity[2])
                        if self._handoff_decide is not None else None)
            observed = self._authority_observed
            if not mismatch:
                self._settling.discard(identity)
                # R-168-R5. THE ORDERING, DEMONSTRATED RATHER THAN ARGUED.
                # The decision above read authority and let go of it; this
                # block takes it back, re-derives if the epoch moved while the
                # reader was between the two, and updates the tables before
                # releasing it. A writer landing in the window either is
                # visible to the decision (it arrived before the read) or moves
                # the epoch (it arrived after), and the second case is the one
                # round 4 lost six times.
                with self._authority_lock:
                    withheld = self._final_decision(identity[2], withheld)
                    # The epoch the decision that leaves this block was derived
                    # from, carried to the retirement with the frame built from
                    # it. R-168-R6/F1.
                    observed = self._authority_observed
                    if withheld is not None and self._handoff_frame is not None:
                        # STILL OWED. The frame below is built by fallible
                        # code -- it writes a receipt, and a receipt that
                        # cannot be written closes the session -- so the
                        # obligation is put back and stays on the books until
                        # the frame exists. Round 4 removed it here and the
                        # close that followed found nothing to retain, so the
                        # client got no answer at all (XD03).
                        self._settling.add(identity)
                    else:
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
                        rule="S3", kind="HANDOFF_GENERATION_MISMATCH")
            return b""
        if withheld is None and self._handoff_record is not None:
            # R-168-R8/F1. THE HANDOFF IS THE SINGLE RECORDER, and round 7 made
            # it the single recorder only for the AUTHORITY answer. Two shapes
            # were left over.
            #
            # The inspection seam built its replacement through
            # `_withhold_result`, which recorded -- so a finding, or an
            # invalidation seen before the scan, wrote a terminal the handoff
            # then superseded, and the receipt named a different outcome from
            # the frame (XS02, XS17). That recorder is silent now.
            #
            # And a crossing with NO authority replacement wrote no terminal at
            # all, so a clean answer and a PROHIBITED_CONTENT refusal both
            # reached the client with nothing in the receipt saying the item
            # had ended (XS13).
            #
            # This method's docstring calls itself the single point where an
            # obligation ends; the terminal belongs where the obligation does.
            # It is taken from the cause the item was actually settled with, so
            # the receipt cannot disagree with the frame.
            settled = self._core.settled_as(record_key)
            self._handoff_record(identity[2],
                                 settled.reason if settled is not None
                                 else "CLEAN",
                                 settled.rule if settled is not None else "S1",
                                 settled is None or settled.reason == "CLEAN")
        if withheld is not None and self._handoff_frame is not None:
            # OUTSIDE the owner, because building the frame writes a receipt
            # and a failed write answers by calling `_close`, which takes this
            # same non-reentrant lock (XB06 deadlocked on exactly that).
            #
            # R-168-R6/F1. AND IN A BOUNDED LOOP, because an authority accepted
            # during the build invalidates the frame just built. The bound is
            # not arbitrary: the precedence is recorded-S3 > cancellation >
            # invalidation, and each is terminal once accepted, so the answer
            # can move at most from None to DESCRIPTOR_CHANGED to
            # REQUEST_CANCELLED -- two changes. The cap is larger than that and
            # exhausting it is a FAULT rather than a stale answer quietly
            # delivered, because a decision that will not hold still long
            # enough to be spent is a session that cannot promise one answer.
            for _ in range(_REDERIVE_LIMIT):
                frame = self._handoff_frame(identity[2], withheld)
                outcome, again, observed = self._retire_prepared(
                    identity, record_key, observed, withheld)
                if outcome == "retired":
                    # R-168-R7. THE RECORD HAPPENS HERE, once, and only now.
                    # The decision can no longer move -- the retirement took
                    # `_authority_lock` to establish that -- so this writes the
                    # answer that actually crosses. Recording per BUILD left a
                    # SETTLED row for every superseded decision, and a
                    # superseded decision is not a settlement: the item settles
                    # once and the receipt has to say so once, or #185's verify
                    # and every reader shaped like XB04 disagree with the wire.
                    if self._handoff_record is not None and \
                            not self._handoff_record(identity[2], withheld):
                        # The receipt could not be written. Nothing crosses;
                        # the client's one answer is the bounded refusal the
                        # route's payer has already sent, because the id stays
                        # unanswered on the wire until a frame reaches it.
                        return b""
                    return frame
                if outcome == "lost":
                    # A close completed while the frame was being prepared. It
                    # found the record still owed, recorded the debt, and pays
                    # it on the way out; handing this frame over as well would
                    # be T6.R1's one answer becoming two.
                    return b""
                withheld = again
                if withheld is None:
                    # Authority moved and the new answer is "let it through",
                    # which cannot happen while the sets only grow -- but if it
                    # ever does, the original is what the decision now asks for.
                    return raw
            self._close("INTERNAL_FAULT",
                        "authority kept moving while an answer was being "
                        "prepared, so no decision could be spent",
                        rule="S3")
            return b""
        return raw

    def _retire_prepared(self, identity, record_key, observed, prepared):
        """End the obligation once the frame for it EXISTS, or say why not.

        R-168-R5. `_retire_record` cannot be reused here and the difference is
        the return value: this caller has a frame in its hand and has to be
        told whether it is still allowed to hand it over. Reading `_closed` in
        a second acquisition after retiring would put the two reads either side
        of a lock release, which is the shape this whole round is about.

        R-168-R6/F1. AND THE EPOCH IS RE-VALIDATED HERE, because round 5's
        protection ended too early. The epoch guarded the decision only until
        `_authority_lock` was released; the frame is then built by fallible
        code, and a cancellation accepted DURING that build -- including one
        released by the re-derivation lock itself -- was invisible to this
        retirement, which spent the stale DESCRIPTOR_CHANGED frame. The item
        was still in `_settling` the whole time, so the route's own `_cancel`
        had correctly left the answer to this gate.

        The re-derivation goes through `release_decision` and NOT through the
        route's gate: XE02_rederive_writer asserts exactly two gate calls and
        this is the third derivation.

        Returns `("retired", None, None)` when the frame stands, `("lost",
        None, None)` when the close or a later generation won and nothing may
        cross, or `("rederive", withheld, observed)` when the answer itself
        changed and the caller must build it again. `prepared` is the decision
        the frame in the caller's hand was built from.
        """
        with self._settlement:
            if self._closed:
                return ("lost", None, None)
            if self._settling_key.get(identity, record_key) != record_key:
                # A later generation owns this record now. Leave it owed; the
                # reader that created it is the one that may retire it.
                return ("lost", None, None)
            with self._authority_lock:
                if self._authority_epoch != observed:
                    # THE DECISION IS COMPARED, NOT THE EPOCH, and the first
                    # draft compared the epoch: every rebuild let the writer
                    # move it again, so the answer was re-derived to the SAME
                    # value forever and the loop hit its cap and closed
                    # INTERNAL_FAULT on a session that had the right answer in
                    # hand. An epoch that moved says the decision MIGHT be
                    # stale; only the decision says whether it is.
                    self._authority_observed = None
                    again = self.release_decision(identity[2],
                                                  origin=identity[0])
                    if again != prepared:
                        return ("rederive", again, self._authority_observed)
                    observed = self._authority_observed
                self._settling.discard(identity)
                self._settling_key.pop(identity, None)
                return ("retired", None, None)

    def _handoff_notification(self, raw):
        """T7.R2 and RC28. A notification crosses only while the session lives.

        There is no id here and so no record, which is exactly why this needed
        its own boundary: `_handoff` decides by the obligation a request left
        behind, and a notification leaves none. What both share is the instant
        the decision is taken -- under `_settlement`, evaluated by the yield, so
        a close that completes while the reader is parked at the line still
        wins.

        `b""` and not `None`, for the reason recorded on `_handoff`: a consumer
        writes what the reader yields, and on a byte stream zero bytes IS
        nothing, needing no special case anywhere.
        """
        with self._settlement:
            if self._closed:
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

    def _close(self, reason, detail, rule="S5", budget=None, *, kind=None):
        """Tear down once, supervise the processes, and RETAIN what is owed.

        `kind` DEFAULTS TO NONE AND THE TEST IS THE GATE (R-CLOSE-KIND). Making
        it required looked like the stronger guarantee and was measured before
        it shipped: it breaks six of the reviewer's controls -- including the
        acceptance file for another PR -- and 21 of our own rows, all with
        TypeError, because a control drives a close positionally to prove what
        happens when one lands mid-flight. A TypeError that fires only in a
        harness is not a guarantee, it is a broken instrument. The AST map test
        in `tests/proxy/test_cause_kind_map.py` asserts that every `_close`
        call site IN THIS PACKAGE supplies a kind, so a new site without one
        fails by name, and an external control that drives a close still runs.

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
                    Cause(reason, rule, budget=budget, detail=detail, kind=kind),
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
            # R-179-R6. `_claimed` TOO. An attempt whose local answer is
            # mid-write is owed a frame exactly as a pending or settling one
            # is; leaving it out here is RC13's "in neither table" window with
            # a third table, and the client waiting on it would be told
            # nothing.
            # R-179-R7. EACH OBLIGATION WITH THE KEY THAT OWNS IT. Round 6
            # walked identities and recomputed `_core_key(identity)`, which
            # returns the LATEST generation -- so two claimed generations of
            # one id retained one refusal between them and the older debt was
            # read under the newer one's key. A claimed obligation is owned by
            # its token; a pending or settling one by the key its record was
            # created with.
            owed = [(identity, self._settling_key.get(identity)
                     or self._core_key(identity))
                    for identity in list(self._pending) + list(self._settling)]
            owed += [(token[:-1], token) for token in self._claimed]
            for identity, core_key in owed:
                if identity[0] != ORIGIN_CLIENT:
                    continue
                # R-179-R7/(d). DELIVERY IS TAKEN, NOT ASSUMED. A local writer
                # already committed to answering this item delivers it; the
                # close retains only what nobody is delivering, so the client
                # gets one frame either way.
                if not self._take_delivery(core_key):
                    continue
                # MERGE: `core_key` and not `self._core_key(identity)` -- the
                # loop already carries the record's own key, and re-deriving it
                # here is the re-read #179 removed.
                own = self._core.terminal_cause(core_key)
                # The budget travels with the reason it belongs to. The
                # envelope refuses an OVER_BUDGET that cannot name which bound
                # broke, and refuses a budget on any reason that has none, so
                # carrying the pair together is what lets either be built.
                if own is not None:
                    self._owed_refusals.append(
                        (identity, own.reason, own.rule))
                    self._budget_for[identity] = getattr(own, "budget", None)
                else:
                    self._owed_refusals.append((identity, reason, rule))
                    self._budget_for[identity] = budget
            self._pending.clear()
            # The debt above is now recorded for both tables, so the record has
            # done its job and must not keep the watcher awake (RC15) or block
            # a later admission (RC17).
            self._settling.clear()
            self._settling_key.clear()
            # R-CLOSE-KIND-R3/(1). Captured BEFORE the tables are cleared,
            # settled BELOW rather than here: the settlement takes the core's
            # lock and taking it under ours is the nesting the reader avoids.
            committed = [(core_key, self._committed_cause[core_key])
                         for _identity, core_key in owed
                         if core_key in self._committed_cause]
            self._claimed.clear()
        # The core settles FIRST WINS, so committing these before the teardown
        # is what makes the receipt agree with the frame the client already has.
        for core_key, (own_reason, own_rule) in committed:
            self._core.settle(core_key, Cause(own_reason, own_rule))
        self._core.teardown(Cause(reason, rule, budget=budget, detail=detail, kind=kind),
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
            # The retained refusal discharges the obligation the close kept,
            # under the token that close recorded it with.
            owed = self._settling_key.get(identity) or self._core_key(identity)
            self._yielded_obligation = owed
            # R-168-R9. AND IT IS A TERMINAL, so it is recorded like one. The
            # drain does not pass through `_handoff`, so round 8's single
            # recorder never saw it and a retained refusal crossed with nothing
            # in the receipt saying the item had ended (XU15) -- the same hole
            # round 8 closed for the ordinary crossing, in the one path that
            # only runs when something has already gone wrong. Pre-existing
            # before round 8 as well; measured on `bb7607b` and `07c5c67`.
            if self._handoff_record is not None:
                self._handoff_record(identity[2], reason, rule, False)
            yield self._client_refusal(identity, reason, rule)

    def control_answer(self, request_id):
        """The frame a proxy-owned request got, or None while it is unanswered."""
        return self._control_answers.get(key(ORIGIN_PROXY, request_id))

    def obligation_for(self, request_id, *, origin=ORIGIN_CLIENT):
        """The token of the LIVE attempt under this id.

        For a caller answering the item that is still pending -- a local
        withhold, a cancellation -- where the live generation is unambiguous
        because admission refuses an id that is already pending or settling.
        A caller answering something that may have finished must carry its own
        token instead; that is what `obligation_of_last_yield` is for.
        """
        return self._core_key(key(origin, request_id))

    def obligation_of_last_yield(self):
        """The token the frame just yielded discharges, or None for a frame
        that discharges nothing (a notification, or the reader saying nothing
        crosses)."""
        return self._yielded_obligation

    def answered_on_the_wire(self, token, *, final=False):
        """This id's answer is committed to the sink, or has reached it.

        R-168-R8/F3. TAKING IS REVERSIBLE, CONFIRMING IS NOT, and collapsing
        the two paid one client twice. The payer wrote a bounded refusal
        straight to the sink -- bytes gone, client answered -- and then the
        close drained a retained refusal for the same id whose authorisation
        failed, `owe_again` put the id back, and the payer answered it a second
        time. An id whose frame has actually MOVED is never owed again; an id
        we merely committed to may be.
        """
        # THE CONFIRMATION NAMES THE GENERATION IT CONFIRMS. Clearing at
        # admission is not enough: a LATE confirmation for the first generation
        # arrives after the second is admitted, and keyed by identity it
        # discarded the new generation's obligation (XU13). A token can only
        # ever confirm its own attempt.
        self._unanswered.discard(token)
        if final:
            self._answered_final.add(token)

    def owe_again(self, token):
        """Give back an obligation we committed to and did not discharge.

        Delivery is taken BEFORE the authorisation, so a concurrent receipt
        failure cannot pay an id whose frame is already on its way; if that
        authorisation then fails the bytes never moved and the client is owed
        again. But only if nothing has ever reached them for this id.

        R-168-R12/(a). RELEASES DELIVERY TOO, now that taking acquires it. A
        give-back that restored the obligation and left delivery held would
        hand back something nobody could ever take again -- the client owed an
        answer no writer is permitted to send.

        R-168-R13/(2), ASTRA OW03 + OW07. THE FINAL CHECK COMES FIRST. Round 12
        discarded delivery and only then asked whether the id was already
        answered, so a give-back for a FINAL answer left the obligation alone
        -- correctly -- while still releasing delivery. `take_delivery` then
        succeeded for an id whose bytes had already reached the client, and a
        stale local writer sent a second response. Nothing is given back for an
        id that has been answered: not the obligation, and not delivery.
        """
        with self._settlement:
            if token in self._answered_final:
                return
            self._delivering.discard(token)
            self._unanswered.add(token)

    def unanswered_clients(self):
        """Every outstanding obligation, FOR LOOKING AT. Grants nothing.

        R-168-R9. This used to be how the payer got its work, and reading a
        list and then marking its entries afterwards is not a claim: a real
        cancellation answered an id while the payer held a stale copy and the
        id was paid twice. Claiming now happens only through
        `take_next_unanswered`, which takes under the owner.

        The method stays because reviewer controls READ it to observe the
        table, and an instrument that can no longer see the state it is
        grading is an instrument broken by a change it had no reason to
        notice. Observation is safe; it is acting on an observation held
        across a lock release that is not.
        """
        return list(self._unanswered)

    def take_obligation(self, token):
        """Claim THIS obligation, or say somebody else already has it.

        R-168-R9/(b). THE ONE OWNERSHIP OPERATION, and every delivery path goes
        through it -- the payer, the local withhold, the cancellation, the
        release. Round 9's first draft had the ordinary paths CONFIRM
        unconditionally while only the payer took, so both answered the same
        request: the payer paid an admitted id whose ordinary answer was still
        in flight, and the client got two frames (RS09).

        A caller that is refused here writes nothing. It has not failed; it has
        learned that this obligation is someone else's to discharge.

        R-168-R12/(a), ASTRA LC01 + LC03. ONE OWNERSHIP SET. This used to take
        only the obligation while `take_delivery` kept a SEPARATE set, so a
        writer could own the obligation and still look unowned to anything
        asking about delivery. The teardown asks `_take_delivery`, saw the
        successful list as nobody's, and retained a second response for a
        request that had already been answered: one answer for the first
        request and TWO for the second, on a real pipe, in 3 of 3 crossings.
        Two sets meant two answers.

        So a taker of one is the owner of the other, acquired in the same
        critical section. A caller refused here writes nothing, whichever half
        was already somebody else's.
        """
        with self._settlement:
            if token not in self._unanswered:
                return False
            return self._take_delivery(token)

    def take_next_unanswered(self, *, origin=ORIGIN_CLIENT):
        """Take ONE outstanding obligation, or None. The only way to get one.

        R-168-R9/(b). `unanswered_clients()` handed out a SNAPSHOT and the
        caller marked each entry afterwards, so the list outlived the owner: a
        real cancellation answered an id while the payer was paused holding a
        stale copy, and the payer paid it again. Two responses, one request.
        `_paying` never helped -- it prevents recursion, not a race.

        Taking is the claim. There is no reading without taking, so nothing a
        caller holds can go stale in its hand, and a token taken or already
        confirmed grants nothing to anyone else. Same law as R-179-R7's
        delivery ownership, which is where this shape comes from.
        """
        with self._settlement:
            # A COPY, because `_take_delivery` discards from `_unanswered` and
            # we no longer return on the first candidate.
            for token in list(self._unanswered):
                if token[0] == origin:
                    # TAKEN, NOT CONFIRMED. The caller has committed to
                    # answering this obligation and nobody else may take it,
                    # but the bytes have not moved: if its write raises, it
                    # gives the obligation back through `owe_again` exactly as
                    # the release path does (XU05). Marking it final here made
                    # the take permanent and lost the answer.
                    #
                    # R-168-R13/(1), ASTRA OW01 + OW02. THROUGH THE SAME SINGLE
                    # ACQUIRE as the other two takers. Round 12 removed the
                    # obligation here by hand and never entered `_delivering`,
                    # so the payer held the obligation while still looking
                    # unowned to anything asking about delivery -- and round 12
                    # had also removed the second-obligation check that used to
                    # stop the local writer. Pause the writer at its acquire,
                    # let the payer take, release it at any of the payer's
                    # three boundaries: TWO responses for one admitted request,
                    # 3 of 3 crossings, where b707bf2 passed 3 of 3. A taker of
                    # either half owns both, and that has to include this one.
                    if self._take_delivery(token):
                        return token
                    # Somebody already owns delivery for this id; it is not
                    # ours to pay. Keep looking rather than reporting the whole
                    # table empty.
                    continue
            return None

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
