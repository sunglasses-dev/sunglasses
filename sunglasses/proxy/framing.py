"""Reading one frame off the wire, and saying exactly what is wrong with it.

T1.R2 fixes the parser and T7.R1 fixes which faults tear a session down, and the
two only make sense together: the same malformed line can be a PROTOCOL fault
that ends the session or a RESOURCE breach that refuses one message, and the
contract separates them deliberately.

  T7.R1  protocol faults are S5: unparseable, invalid UTF-8, duplicate key,
         not JSON-RPC 2.0, both result and error, invalid id type.
  T4.R4(2)  structural and resource breaches are NOT S5. Depth, nodes and frame
         size are S3 OVER_BUDGET with the budget named, and the session may
         continue.

Collapsing those two into "bad frame" is the mistake this module exists to avoid.
A depth breach is a message too big to inspect, which says nothing about whether
the stream is still trustworthy; a duplicate key means the sender and we do not
agree on what the message SAYS, and nothing after it can be trusted.
"""
from __future__ import annotations

import json

# T8.R1, T1.R2. Frozen for 0.6.0.
MAX_FRAME_BYTES = 4_194_304
MAX_DEPTH = 64
MAX_NODES = 100_000

# T7.R1 / T4.R4. The rule is WHY the session reacts as it does; the reason is
# what the client is told. They are separate fields because one cause maps to
# one of each and a reader has to be able to see both.
S3 = "S3"
S5 = "S5"

MALFORMED_UPSTREAM = "MALFORMED_UPSTREAM"
MALFORMED_CLIENT = "MALFORMED_CLIENT"
OVER_BUDGET = "OVER_BUDGET"

# T4.R4(2): the budget that was breached, named. A receipt saying OVER_BUDGET
# without saying WHICH bound is not gradeable against the fixtures.
BUDGET_FRAME = "frame"
BUDGET_DEPTH = "depth"
BUDGET_NODES = "nodes"


class NotJsonNumber(ValueError):
    """`NaN`, `Infinity` or `-Infinity` appeared in the frame.

    `json.loads` accepts all three by default. They are a Python extension and
    not JSON, no MCP peer is entitled to send them, and they poison every
    numeric comparison downstream: a budget check against NaN is false whichever
    way it is written, so a counter of NaN passes "at most" and "at least" at
    once. Found by ASTRA's independent checks, not by mine.
    """


class DuplicateKey(ValueError):
    """Two entries for one key in one object.

    Its own exception rather than a generic ValueError because the contract
    treats it as a PROTOCOL fault and not as a parse failure, and the two lead
    to different rules.
    """


def _reject_constant(literal):
    raise NotJsonNumber(f"{literal} is not a JSON number")


def _no_duplicate_keys(pairs):
    """T1.R2's `object_pairs_hook`.

    `json.loads` keeps the LAST value for a repeated key and says nothing. That
    is a disagreement about what the message says, between us and whatever wrote
    it, and it is the classic way to show a scanner one value and a server
    another. Rejecting it is the only reading that cannot be played.
    """
    seen = set()
    for position, (key, _value) in enumerate(pairs):
        if key in seen:
            # The KEY IS NOT QUOTED. It is attacker controlled text and `detail`
            # is carried into a receipt, so naming it here would put an
            # untrusted string into the evidence. Position and length identify
            # it for anyone holding the frame, and neither reproduces it.
            raise DuplicateKey(
                f"duplicate key at position {position}, {len(str(key))} "
                f"characters; the key itself is withheld from the receipt")
        seen.add(key)
    return dict(pairs)


class Frame:
    """A parsed frame, or the reason there is not one.

    `ok` is never inferred from `message` being present, because a fault that
    still produced a dict is exactly the case worth getting right.
    """

    __slots__ = ("ok", "message", "rule", "reason", "budget", "detail", "bytes")

    def __init__(self, *, ok, message=None, rule=None, reason=None, budget=None,
                 detail=None, size=0):
        self.ok = ok
        self.message = message
        self.rule = rule
        self.reason = reason
        self.budget = budget
        self.detail = detail
        self.bytes = size

    def __bool__(self):
        return self.ok

    def as_receipt(self):
        """An ALLOWLIST. `detail` is deliberately absent.

        Every field here is produced by us from a fixed vocabulary. `detail`
        is prose built around peer-supplied material, and twice it carried that
        material verbatim: the duplicate key, and then the rejected `jsonrpc`
        version. Both were found by review, not by me, which is the argument for
        an allowlist over a denylist. `detail` stays on the object for logs and
        exceptions and never crosses into evidence.
        """
        return {"ok": self.ok, "rule": self.rule, "reason": self.reason,
                "budget": self.budget, "bytes": self.bytes}

    def __repr__(self):
        if self.ok:
            return f"<Frame ok {self.bytes}B>"
        return f"<Frame {self.rule}/{self.reason}{'/' + self.budget if self.budget else ''}>"


def _shape(value):
    """Depth and node count in ONE walk, iteratively.

    Iteratively because the thing being measured is how deeply nested the input
    is, and a recursive measurer fails first on exactly the input it exists to
    measure.
    """
    depth = 0
    nodes = 0
    stack = [(value, 1)]
    while stack:
        node, level = stack.pop()
        nodes += 1
        if level > depth:
            depth = level
        if nodes > MAX_NODES:
            return depth, nodes          # no point counting the rest
        if isinstance(node, dict):
            for key, item in node.items():
                nodes += 1               # the key is a node of its own
                stack.append((item, level + 1))
        elif isinstance(node, list):
            for item in node:
                stack.append((item, level + 1))
    return depth, nodes


def valid_id(value):
    """T1.R2: ids are string, number or null, and the JSON type is retained.

    `isinstance(True, int)` is True in Python, so a bool reaches a naive number
    check as a number. `true` is not a valid JSON-RPC id and a proxy that
    accepted it would correlate a reply to something the client never asked,
    so bool is excluded explicitly rather than left to a resemblance.
    """
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    return isinstance(value, (str, int, float))


def bounded_lines(source, limit=MAX_FRAME_BYTES, unterminated=None):
    """Frames, read with a ceiling, instead of `readline` with none.

    T1.R2's bounded reader, which ASTRA's review noted was absent.
    `iter(source.readline, b"")` reads until it finds a newline however far away
    that is, and checking the wire limit against the line it returns applies the
    bound AFTER the unbounded thing has already happened. An upstream that never
    sends a newline makes the proxy allocate until it dies, inside the one
    component whose job is to survive a hostile upstream.

    An over-long frame is yielded as a bounded PREFIX so the caller refuses it
    through the ordinary path rather than through an exception, and the rest of
    that frame is drained and discarded. Draining too little resumes inside the
    frame just refused, which is the resynchronisation T7.R2 forbids; draining
    too much swallows the next message.
    """
    buffer = b""
    # The caller's list, when it wants to know; a private one otherwise, so the
    # generator never has to test for None in the loop.
    unterminated = [] if unterminated is None else unterminated
    while True:
        chunk = source.read1(65536) if hasattr(source, "read1") else source.read(65536)
        if not chunk:
            # AR15. A TAIL IS NOT A FRAME. This used to yield whatever was in
            # the buffer at EOF, which handed the caller a partial line as
            # though a complete one had arrived: on the client direction that
            # forwarded an unterminated request to the server, which is the
            # mediator delivering something nobody finished sending.
            #
            # "A frame is its bytes including the LF" is the rule two lines
            # below, and it decides this case too. The tail is reported rather
            # than dropped silently -- `unterminated_tail` is what the caller
            # reads to close the session, since a peer that stops mid-frame has
            # not made an ordinary clean ending.
            if buffer:
                unterminated.append(buffer)
            return
        buffer += chunk
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            # THE TERMINATOR STAYS ON. A frame is its bytes including the LF:
            # T8.R1 bounds the "raw wire frame incl. LF", and a reader that
            # strips it measures one byte short, so a frame exactly one over the
            # inclusive cap passes. Keeping it also means what the reader
            # forwards is byte-for-byte what arrived, rather than a
            # reconstruction that happens to look the same.
            yield line + b"\n"
        if len(buffer) > limit:
            yield buffer[:limit + 1]
            buffer = b""
            while True:
                chunk = (source.read1(65536) if hasattr(source, "read1")
                         else source.read(65536))
                if not chunk:
                    return
                if b"\n" in chunk:
                    buffer = chunk.split(b"\n", 1)[1]
                    break


def _envelope_fault(message):
    """Every frame is a request, a notification or a response, and nothing else.

    A frame that is none of the three has no meaning to act on, and the shapes
    that reach this check are not exotic. `{"jsonrpc":"2.0"}` carries nothing.
    A `result` with no `id` is a response to nobody. A `method` that is not a
    string is not a method name. An `error` that is not an object has no code.

    The parser accepted all four before ASTRA's checks found them, because it
    validated the FIELDS a frame had and never asked whether the combination was
    a frame at all.
    """
    has_method = "method" in message
    has_id = "id" in message
    has_result = "result" in message
    has_error = "error" in message

    # MUTUALLY EXCLUSIVE, checked before anything else. The first version
    # returned as soon as it saw a `method`, so a frame carrying a method AND a
    # result was accepted as a request and its response half was never looked
    # at. A frame that is both is not "a request with extra"; it is two claims
    # about what it is, and acting on either one is a guess.
    if has_method and (has_result or has_error):
        return "the frame carries a method and a response member at once"
    if has_result and has_error:
        return "both result and error are present"

    if has_method:
        if not isinstance(message["method"], str):
            return (f"method is {type(message['method']).__name__}, not a "
                    f"string")
        if "params" in message and not isinstance(message["params"],
                                                  (dict, list)):
            # JSON-RPC 2.0 allows params to be a structured value only.
            return (f"params is {type(message['params']).__name__}, which is "
                    f"not a structured value")
        return None                    # request when it has an id, else a notification
    if has_result or has_error:
        if not has_id:
            return "a response carries no id, so it answers nobody"
        if has_error:
            error = message["error"]
            if not isinstance(error, dict):
                return f"error is {type(error).__name__}, not an object"
            # An error object without a code and a message carries no more
            # information than its own presence.
            if "code" not in error or "message" not in error:
                return "the error object has no code or no message"
            if not isinstance(error["code"], int) or isinstance(error["code"],
                                                               bool):
                return "the error code is not an integer"
            if not isinstance(error["message"], str):
                return "the error message is not a string"
        return None
    return "the frame is neither a request, a notification nor a response"


def parse_frame(raw, *, origin="upstream"):
    """One line of wire bytes to a Frame, with the cause named.

    `origin` decides only which side is blamed, MALFORMED_UPSTREAM or
    MALFORMED_CLIENT (T7.R1, T7.R3). It never changes what counts as a fault.
    """
    malformed = MALFORMED_UPSTREAM if origin == "upstream" else MALFORMED_CLIENT

    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogatepass")
    # T8.R1 bounds the frame INCLUDING its terminator, so the size is measured
    # before the terminator is removed for parsing. Measuring the stripped line
    # lets a frame exactly one byte over the inclusive cap through.
    size = len(raw)
    body = raw[:-1] if raw.endswith(b"\n") else raw

    # T8.R1 BEFORE the parse. A frame over the wire limit is refused without
    # being parsed, because parsing it is the cost the bound exists to refuse.
    if size > MAX_FRAME_BYTES:
        return Frame(ok=False, rule=S3, reason=OVER_BUDGET, budget=BUDGET_FRAME,
                     detail=f"{size} bytes over the {MAX_FRAME_BYTES} byte frame limit",
                     size=size)

    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as bad:
        return Frame(ok=False, rule=S5, reason=malformed,
                     detail=f"invalid UTF-8 at byte {bad.start}", size=size)

    try:
        message = json.loads(text, object_pairs_hook=_no_duplicate_keys,
                             parse_constant=_reject_constant)
    except NotJsonNumber as constant:
        return Frame(ok=False, rule=S5, reason=malformed,
                     detail=str(constant), size=size)
    except DuplicateKey as duplicated:
        return Frame(ok=False, rule=S5, reason=malformed,
                     detail=str(duplicated), size=size)
    except RecursionError:
        # Nesting deep enough to exhaust the parser. The cause is the same as a
        # measured depth breach and it is reported the same way, because "we
        # could not get far enough in to measure it" is not a different fact
        # about the message from "it is too deep".
        return Frame(ok=False, rule=S3, reason=OVER_BUDGET, budget=BUDGET_DEPTH,
                     detail="nesting exhausted the parser", size=size)
    except ValueError as broken:
        return Frame(ok=False, rule=S5, reason=malformed,
                     detail=f"unparseable: {broken}", size=size)

    depth, nodes = _shape(message)
    if depth > MAX_DEPTH:
        return Frame(ok=False, rule=S3, reason=OVER_BUDGET, budget=BUDGET_DEPTH,
                     detail=f"depth {depth} over {MAX_DEPTH}", size=size)
    if nodes > MAX_NODES:
        return Frame(ok=False, rule=S3, reason=OVER_BUDGET, budget=BUDGET_NODES,
                     detail=f"{nodes} nodes over {MAX_NODES}", size=size)

    if not isinstance(message, dict):
        return Frame(ok=False, rule=S5, reason=malformed,
                     detail=f"top level is {type(message).__name__}, not an object",
                     size=size)
    if message.get("jsonrpc") != "2.0":
        version = message.get("jsonrpc")
        return Frame(ok=False, rule=S5, reason=malformed,
                     detail=f"jsonrpc is not '2.0' (a "
                            f"{type(version).__name__} of "
                            f"{len(str(version))} characters)",
                     size=size)
    envelope = _envelope_fault(message)
    if envelope:
        return Frame(ok=False, rule=S5, reason=malformed, detail=envelope,
                     size=size)
    if "id" in message and not valid_id(message["id"]):
        return Frame(ok=False, rule=S5, reason=malformed,
                     detail=f"id is {type(message['id']).__name__}, which is not "
                            f"a string, number or null",
                     size=size)

    return Frame(ok=True, message=message, size=size)
