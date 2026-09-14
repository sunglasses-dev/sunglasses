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

from . import framing
from .session import Cause, Session as CoreSession

ORIGIN_CLIENT = "client"
ORIGIN_UPSTREAM = "upstream"

# T6.R6. Bounded, because a tombstone table that grows with the session is a
# memory bound a peer controls.
TOMBSTONE_LIMIT = 10_000


def key(origin, request_id):
    """T6.R6's identity: origin, JSON type, value.

    The type is in the key rather than compared afterwards, because `"2001"` and
    `2001` are equal to a human reading a receipt and must never be equal to
    this. Python would keep them distinct in a dict on its own; naming the type
    makes the rule legible and survives anyone who later "simplifies" the key to
    the value.
    """
    return (origin, type(request_id).__name__, request_id)


class Session:
    """The correlation table, the tombstones, and the decision to stop reading."""

    def __init__(self):
        self._core = CoreSession()
        self._pending: dict = {}          # key -> method
        self._answered: set = set()
        self._tombstones: list = []       # keys, oldest first
        self._closed: tuple | None = None

    # ── admission ───────────────────────────────────────────────────────────
    def admit_request(self, request_id, *, method, origin):
        """T6.R6. A duplicate typed id from the client closes the session."""
        if self._closed:
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
        self._pending[identity] = method
        self._core.admit(identity, method=method, origin=origin)
        return True

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
        self._core.settle(identity, Cause("CLEAN", "S1"))
        # T6.R1: C's TYPED id, returned as it was issued.
        return {"jsonrpc": "2.0", "id": request_id, "result": (frame or {}).get(
            "result", {})}

    def _shape_matches(self, identity, frame):
        """T2.R0 and G2-10. What a `tools/call` result must look like.

        This is the check that needed the pending METHOD, and the reason
        `_owed` storing a bare timestamp made it impossible. A response is only
        well formed relative to the request it answers.
        """
        method = self._pending.get(identity)
        result = frame.get("result")
        if method == "tools/call" and isinstance(result, dict):
            if "content" in result and not isinstance(result["content"], list):
                return False
        if method == "tools/list" and isinstance(result, dict):
            if "tools" in result and not isinstance(result["tools"], list):
                return False
        return True

    def settle_from(self, origin, request_id, reason, rule):
        """T6.R3. An upstream REQUEST is answered in U's id namespace, never C's."""
        identity = key(origin, request_id)
        if identity not in self._pending:
            return None
        self._pending.pop(identity)
        self._answered.add(identity)
        return self._core.settle(identity, Cause(reason, rule))

    def cancel(self, request_id, *, origin):
        """T6.R5 and T6.R6. The id is retired and tombstoned for the session."""
        identity = key(origin, request_id)
        self._pending.pop(identity, None)
        self._remember_tombstone(identity)
        self._core.settle(identity, Cause("REQUEST_CANCELLED", "S6"))
        return identity

    def _remember_tombstone(self, identity):
        self._tombstones.append(identity)
        if len(self._tombstones) > TOMBSTONE_LIMIT:
            # T6.R6 caps this; overflow closes the session rather than silently
            # forgetting, because a forgotten tombstone lets a cancelled id be
            # reused and that is the thing the table exists to prevent.
            self._close("OVERLOADED", "the tombstone table overflowed")

    # ── reading ─────────────────────────────────────────────────────────────
    def read_upstream(self, stream):
        """Yield the frames a client should see. Stops for good at a fault.

        T7.R2's last sentence is the whole design: never resynchronise at the
        next newline. Everything after a frame we could not trust is discarded
        WITHOUT being parsed, because parsing it is how a proxy talks itself
        into continuing.
        """
        for raw in framing.bounded_lines(_as_reader(stream),
                                         framing.MAX_FRAME_BYTES):
            if self._closed:
                return
            parsed = framing.parse_frame(raw, origin=ORIGIN_UPSTREAM)
            if not parsed:
                self._close(parsed.reason, parsed.detail, rule=parsed.rule)
                return
            message = parsed.message
            if "id" not in message:
                yield raw                        # a notification, forwarded
                continue
            answer = self.deliver_response(origin=ORIGIN_UPSTREAM,
                                           request_id=message["id"],
                                           frame=message)
            if answer is None:
                return
            yield raw

        # T7.R1. EOF is not a clean ending while the client is still owed.
        if self._pending and not self._closed:
            self._close("MALFORMED_UPSTREAM",
                        "upstream exited with calls still pending")

    # ── outcome ─────────────────────────────────────────────────────────────
    def _close(self, reason, detail, rule="S5"):
        if self._closed:
            return
        self._closed = (reason, rule)
        self._core.teardown(Cause(reason, rule, detail=detail))
        self._pending.clear()

    def closed_with(self):
        return self._closed

    def answer_for(self, request_id, *, origin):
        return self._core.settled_as(key(origin, request_id))

    @property
    def events(self):
        return self._core.events


def _as_reader(stream):
    """Accept bytes or a file object, so a caller need not wrap a fixture."""
    if hasattr(stream, "read"):
        return stream
    import io
    return io.BytesIO(stream)
