"""What gets inspected, on which channel, and what counts against the budget.

T2's table and T3.R1's accounting. Written against
`tests/test_proxy_selector.py`, committed first from the rows.

THE TWO ACCOUNTINGS ARE SEPARATE AND THAT IS THE POINT. T2.R0 freezes coverage:
every string leaf AND every object KEY, recursively, everything except the fixed
protocol scalars. T3.R1 freezes the content-byte count: only string VALUES at
content positions, keys excluded, the `type` and `role` discriminants excluded,
duplicates counted twice.

A key is inspected and does not count. One function serving both is the obvious
economy and it is wrong in both directions simultaneously, because it must
either stop inspecting keys or start charging for them, and the rows forbid each
of those in turn. So there are two functions, they walk the same tree, and they
disagree on purpose.
"""
from __future__ import annotations

import json

MESSAGE = "message"
API_RESPONSE = "api_response"
CONTROL = "control"

UNSUPPORTED_CONTENT = "UNSUPPORTED_CONTENT"
UNINSPECTED_METHOD = "UNINSPECTED_METHOD"

# T2.R0. The only things excluded from COVERAGE: fixed protocol scalars that the
# schema validates. Everything else, including every key, is inspected.
_PROTOCOL_SCALARS = frozenset({
    "jsonrpc", "id", "code", "isError", "nextCursor", "protocolVersion",
    "progress", "total",
})

# T3.R1. Excluded from the CONTENT BYTE count on top of all keys: the schema
# discriminants, whose vocabulary is fixed. Charging them makes an identical
# payload cost more in one shape than in another.
_DISCRIMINANTS = frozenset({"type", "role"})

# T201 and T202. The containers whose CONTENTS the server defines. Everything
# inside one of these is content, whatever it happens to be named.
#
# The exclusions above are positions in OUR protocol, and they were being
# applied by name at any depth. `structuredContent` is arbitrary JSON the tool
# chooses the shape of, `_meta` is extension data and `arguments` is tool
# input, so a key called `id` or `type` in there was named by the peer and is
# not a protocol member at all. Name-based skipping charged those bytes as zero
# and left the key out of the coverage leaves, which means a server could hide
# a payload under `structuredContent.id` and have it inspected by nothing.
#
# This is the same shape of defect as every other one this package has had:
# recognising the NAME is not recognising the POSITION.
_OPAQUE_CONTAINERS = frozenset({"structuredContent", "_meta", "arguments"})

# T2's rows, as a table rather than a chain of conditionals.
_REQUEST_CHANNEL = {
    "initialize": MESSAGE,          # T2.R1
    "tools/call": MESSAGE,          # T2.R3
    "tools/list": CONTROL,          # T2.R6
    "resources/read": MESSAGE,      # T2.R8
    "prompts/get": MESSAGE,         # T2.R10
}
_RESULT_CHANNEL = {
    "initialize": API_RESPONSE,     # T2.R2
    "tools/call": API_RESPONSE,     # T2.R4
    "tools/list": API_RESPONSE,     # T2.R7
    "resources/read": API_RESPONSE, # T2.R9
    "prompts/get": API_RESPONSE,    # T2.R11
}

# T2.R14. Exactly three shapes may be COMPLETE with no leaves at all.
_ZERO_LEAF_METHODS = frozenset({"ping", "notifications/initialized"})

# T207. The notifications this protocol defines, ENUMERATED. The refusal table
# accepted anything beginning `notifications/`, which is a prefix and not a
# vocabulary: `notifications/review-unknown` was forwarded untouched in both
# directions. A prefix check is the same defect as a name check -- recognising
# the shape of a name is not recognising the name.
KNOWN_NOTIFICATIONS = frozenset({
    "notifications/initialized",
    "notifications/message",
    "notifications/cancelled",
    "notifications/progress",
    "notifications/tools/list_changed",
    "notifications/resources/list_changed",
    "notifications/resources/updated",
    "notifications/prompts/list_changed",
    "notifications/roots/list_changed",
})

# T206. `ping` is a method the protocol REQUIRES an answer to, and it was
# missing here, so a client's ping was refused UNINSPECTED_METHOD. It has no
# channel because it carries nothing, which is why it lives in the no-leaf set
# rather than in a channel table, and why leaving it out was easy to miss.
KNOWN_METHODS = (frozenset(_REQUEST_CHANNEL) | frozenset(_RESULT_CHANNEL)
                 | _ZERO_LEAF_METHODS | KNOWN_NOTIFICATIONS)

# T205. The content block types this protocol defines. `image` and `audio` are
# defined and UNSUPPORTED; anything else is not a block we can read at all.
_SUPPORTED_BLOCK_TYPES = frozenset({"text", "resource"})


def channel_for(method, direction):
    """T2's channel column. A rule is scoped to a channel, so choosing the wrong
    one silently disables every rule written for the right one."""
    if method.startswith("notifications/"):
        # T2.R12 upstream, T2.R13 client.
        return API_RESPONSE if direction == "result" else MESSAGE
    # T204. A correlated ERROR is a reply, and its message and data are the
    # server's own text arriving in answer to a client request. That is the
    # api_response channel. Returning no channel scoped every api_response rule
    # out of the one reply shape built to carry text back, which disabled them
    # silently rather than loudly.
    if direction == "result" and method == "error":
        return API_RESPONSE
    table = _RESULT_CHANNEL if direction == "result" else _REQUEST_CHANNEL
    return table.get(method)


def coverage_leaves(value, path=""):
    """T2.R0. Every string leaf and every object KEY, in document order.

    Keys are yielded as leaves of their own because a key is content: a tool
    named for an instruction, or a `_meta` member whose NAME carries the
    payload, is inspected here and nowhere else.

    Numbers and booleans are yielded in their JSON spelling, per T3.R1, so a
    rule matching text sees them the way the wire wrote them rather than the way
    Python prints them: `false`, not `False`.
    """
    out = []
    _walk_coverage(value, path, out)
    return out


def _walk_coverage(value, path, out, opaque=False):
    if isinstance(value, dict):
        for key, item in value.items():
            here = f"{path}/{key}" if path else key
            if opaque or key not in _PROTOCOL_SCALARS:
                out.append((f"{here}#key", key))
            _walk_coverage(item, here, out,
                           opaque or key in _OPAQUE_CONTAINERS)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk_coverage(item, f"{path}[{index}]", out, opaque)
    elif isinstance(value, str):
        out.append((path, value))
    elif value is None or isinstance(value, (bool, int, float)):
        out.append((path, json.dumps(value)))


def content_bytes(value):
    """T3.R1 and T8.R2. Decoded UTF-8 bytes of string VALUES at content
    positions, and nothing else.

    Keys are excluded, discriminants are excluded, duplicates count twice, and
    separators are not counted because they are ours rather than the peer's.
    Bytes and not characters: counting characters hands an attacker three times
    the budget in any script that is not ASCII.
    """
    return _walk_bytes(value, parent_key=None, opaque=False)


def _walk_bytes(value, parent_key, opaque):
    if isinstance(value, dict):
        return sum(_walk_bytes(item, key, opaque or key in _OPAQUE_CONTAINERS)
                   for key, item in value.items())
    if isinstance(value, list):
        return sum(_walk_bytes(item, parent_key, opaque) for item in value)
    if isinstance(value, str):
        if not opaque and (parent_key in _DISCRIMINANTS
                           or parent_key in _PROTOCOL_SCALARS):
            return 0
        return len(value.encode("utf-8", "surrogatepass"))
    return 0


def zero_leaves_is_complete(method, message):
    """T2.R14. Three shapes, and the third has a condition attached.

    A `tools/call` result whose `content` is `[]` WITH NO OTHER MEMBERS. An
    empty content list arriving beside a `structuredContent` object has leaves,
    and calling that complete would pass the other members uninspected, which is
    the reading the row's own wording rules out.
    """
    if method in _ZERO_LEAF_METHODS:
        return True
    if method == "tools/call":
        return message.get("content") == [] and set(message) == {"content"}
    return False


def unsupported(method, result):
    """T2.R4, R9 and R11. Binary content is UNSUPPORTED, never skipped.

    Skipping a blob and inspecting the rest reports a clean scan of a message we
    did not read, which is the most dangerous kind of clean there is.
    """
    for block in result.get("content") or []:
        # T205. `continue` was a SILENT SKIP, which is the one thing the row
        # forbids. A block that is not an object, or whose type is not one this
        # protocol defines, is content we cannot read; inspecting the rest and
        # reporting clean describes a message we did not read.
        if not isinstance(block, dict):
            return UNSUPPORTED_CONTENT
        if block.get("type") not in _SUPPORTED_BLOCK_TYPES:
            return UNSUPPORTED_CONTENT
        resource = block.get("resource")
        if isinstance(resource, dict) and "blob" in resource:
            return UNSUPPORTED_CONTENT
    for entry in result.get("contents") or []:
        if isinstance(entry, dict) and "blob" in entry:
            return UNSUPPORTED_CONTENT
    for entry in result.get("messages") or []:
        if not isinstance(entry, dict):
            return UNSUPPORTED_CONTENT
        content = entry.get("content")
        if isinstance(content, dict):
            if content.get("type") not in _SUPPORTED_BLOCK_TYPES:
                return UNSUPPORTED_CONTENT
            resource = content.get("resource")
            if isinstance(resource, dict) and "blob" in resource:
                return UNSUPPORTED_CONTENT
    return None


class Refusal:
    __slots__ = ("reason", "answer_to", "forward")

    def __init__(self, reason, answer_to, forward=False):
        self.reason = reason
        self.answer_to = answer_to
        self.forward = forward

    def __repr__(self):
        return f"<Refusal {self.reason} to {self.answer_to}>"


def refusal(method, direction, *, origin):
    """T2.R15 and T2.R16. Who is answered, and who never sees it.

    The two rows are mirror images and the mirror is the security property. An
    upstream request is answered UPSTREAM and the client never sees it, because
    forwarding it would let the server drive the client through us, which is the
    thing a mediator exists to prevent. A client's unknown method is answered to
    the CLIENT and upstream never sees it.
    """
    if direction != "request":
        return None
    if origin == "upstream":
        # Every upstream request is uninspected by this table, named or not.
        return Refusal(UNINSPECTED_METHOD, answer_to="upstream")
    if method in KNOWN_METHODS:
        return None
    # T207. An unknown notification is REFUSED and not forwarded. The prefix
    # test that used to stand here accepted any name at all under
    # `notifications/`, so a peer could send one through untouched by choosing
    # its own suffix.
    return Refusal(UNINSPECTED_METHOD, answer_to="client", forward=False)
