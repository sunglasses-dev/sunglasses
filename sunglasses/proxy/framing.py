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


class DuplicateKey(ValueError):
    """Two entries for one key in one object.

    Its own exception rather than a generic ValueError because the contract
    treats it as a PROTOCOL fault and not as a parse failure, and the two lead
    to different rules.
    """


def _no_duplicate_keys(pairs):
    """T1.R2's `object_pairs_hook`.

    `json.loads` keeps the LAST value for a repeated key and says nothing. That
    is a disagreement about what the message says, between us and whatever wrote
    it, and it is the classic way to show a scanner one value and a server
    another. Rejecting it is the only reading that cannot be played.
    """
    seen = set()
    for key, _value in pairs:
        if key in seen:
            raise DuplicateKey(f"duplicate key {key!r}")
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
        return {"ok": self.ok, "rule": self.rule, "reason": self.reason,
                "budget": self.budget, "detail": self.detail, "bytes": self.bytes}

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


def parse_frame(raw, *, origin="upstream"):
    """One line of wire bytes to a Frame, with the cause named.

    `origin` decides only which side is blamed, MALFORMED_UPSTREAM or
    MALFORMED_CLIENT (T7.R1, T7.R3). It never changes what counts as a fault.
    """
    malformed = MALFORMED_UPSTREAM if origin == "upstream" else MALFORMED_CLIENT

    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogatepass")
    size = len(raw)

    # T8.R1 BEFORE the parse. A frame over the wire limit is refused without
    # being parsed, because parsing it is the cost the bound exists to refuse.
    if size > MAX_FRAME_BYTES:
        return Frame(ok=False, rule=S3, reason=OVER_BUDGET, budget=BUDGET_FRAME,
                     detail=f"{size} bytes over the {MAX_FRAME_BYTES} byte frame limit",
                     size=size)

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as bad:
        return Frame(ok=False, rule=S5, reason=malformed,
                     detail=f"invalid UTF-8 at byte {bad.start}", size=size)

    try:
        message = json.loads(text, object_pairs_hook=_no_duplicate_keys)
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
        return Frame(ok=False, rule=S5, reason=malformed,
                     detail=f"jsonrpc is {message.get('jsonrpc')!r}, not '2.0'",
                     size=size)
    if "result" in message and "error" in message:
        # T7.R1. A response is one or the other; a frame claiming both leaves
        # the reader to choose, and whichever it chooses the sender may have
        # meant the other.
        return Frame(ok=False, rule=S5, reason=malformed,
                     detail="both result and error are present", size=size)
    if "id" in message and not valid_id(message["id"]):
        return Frame(ok=False, rule=S5, reason=malformed,
                     detail=f"id is {type(message['id']).__name__}, which is not "
                            f"a string, number or null",
                     size=size)

    return Frame(ok=True, message=message, size=size)
