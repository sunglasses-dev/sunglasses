"""The only thing the client is ever told, built from an allowlist.

T4.R7. Written against `tests/test_proxy_envelope.py`, committed first.

The row's last sentence is the specification: never payload, never secret, never
descriptor text, never exception or worker or stderr text, never arbitrary ids.
Everything else in this package decides WHETHER to withhold something. This
decides what crosses the boundary when we do, which makes it the one structure
an adversary is guaranteed to read, and the only one where a mistake is
published rather than merely made.

So it is built by NAMING each field, never by copying a mapping and removing
what looks dangerous. Those are not two spellings of one idea. A denylist is a
claim that you thought of everything that could be added later; an allowlist
makes the next person add a line before their field can escape. This package has
already leaked peer material into evidence three times through fields that were
built the other way, each time through a caller with an entirely good reason, so
the constructor here takes `**ignored` and drops it on the floor rather than
letting a caller's extra keyword ride along.
"""
from __future__ import annotations

WITHHELD_CODE = -32070
WITHHELD_MESSAGE = "SUNGLASSES_WITHHELD"

# T4.R5's catalog, the reasons an envelope may name. A reason outside it would
# be a free text field wearing a respectable name.
REASONS = frozenset({
    "CLEAN", "NO_FINDING_KNOWN_DETECTOR_GAP", "PROHIBITED_CONTENT",
    "PROHIBITED_SECRET", "REVIEW_REQUIRED", "SCAN_EXCEPTION", "SCAN_DEADLINE",
    "OVER_BUDGET", "OVERLOADED", "UNSUPPORTED_CONTENT", "UNINSPECTED_METHOD",
    "UNSUPPORTED_PROTOCOL", "MALFORMED_UPSTREAM", "MALFORMED_CLIENT",
    "REQUEST_CANCELLED", "APPROVAL_REQUIRED", "DESCRIPTOR_CHANGED",
    "RECEIPT_IO_ERROR", "INCOMPLETE_SESSION", "ROUTE_UNVERIFIED",
    "CONFIG_CONFLICT", "CONFIG_IO_ERROR",
})

RULES = frozenset({"S1", "S2", "S3", "S4", "S5", "S6", "S7"})

# T409. The worker's own status vocabulary, frozen here for the same reason the
# reasons are. `status` is copied out of a worker result, so an open field is a
# worker choosing text that lands in the structure an attacker reads. It is
# written out rather than imported from `worker` on purpose: this module names
# what may cross the boundary and takes no dependency that could widen the set
# from elsewhere. `tests/test_proxy_envelope.py` asserts the two agree, so the
# duplication is guarded rather than hoped about.
STATUSES = frozenset({"complete", "incomplete", "exception", "deadline",
                      "cancelled", "not_run"})
BUDGETS = frozenset({"content", "frame", "depth", "nodes"})

# T4.R7. Bounded so a worker cannot make the envelope arbitrarily large, and
# ORDERED so the bound is deterministic.
MAX_RULE_IDS = 32


def _number(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} is {value!r}, which is not a number")
    if value < 0 or value != value or value in (float("inf"), float("-inf")):
        raise ValueError(f"{field} is {value!r}, which is not a usable count")
    return value


def withheld(*, request_id, reason_code, rule, accepted, status,
             inspection_complete, inspected_utf8_bytes, observed_content_bytes,
             elapsed_ms, rule_ids=(), catalog=frozenset(), budget=None,
             **ignored):
    """T4.R7's envelope, and nothing else.

    `**ignored` is deliberate and is the point of the design. A caller with a
    detail string, a worker's stderr or an exception to explain will pass it,
    because that is what a helpful caller does, and it is dropped here rather
    than reaching the wire. The tests push exactly those four through it.
    """
    if reason_code not in REASONS:
        raise ValueError(f"{reason_code!r} is not in the frozen reason catalog")
    if rule not in RULES:
        raise ValueError(f"{rule!r} is not one of S1 to S7")

    # v5.1: declared, and null unless the reason is a budget breach. Both
    # directions, because a budget naming nothing and a budget on a reason that
    # has none are each a receipt that cannot be graded.
    if reason_code == "OVER_BUDGET":
        if budget not in BUDGETS:
            raise ValueError(
                f"reason OVER_BUDGET needs one of {sorted(BUDGETS)}, got "
                f"{budget!r}; a breach that cannot say which bound broke cannot "
                f"be compared to a fixture")
    elif budget is not None:
        raise ValueError(
            f"budget {budget!r} is set on reason {reason_code}, which is not a "
            f"budget breach, so the value describes nothing")

    if not isinstance(accepted, bool):
        raise ValueError(f"accepted is {accepted!r}, not a boolean")
    if not isinstance(inspection_complete, bool):
        raise ValueError(
            f"inspection_complete is {inspection_complete!r}, not a boolean")
    if status not in STATUSES:
        raise ValueError(
            f"status {status!r} is not one of {sorted(STATUSES)}; a status the "
            f"worker chose the spelling of is free text in the one structure "
            f"an adversary is guaranteed to read")

    # CATALOG ONLY, deduplicated, ORDERED BY CATALOG ID ASCENDING, then bounded,
    # in that order. An id we cannot vouch for is not evidence, and echoing one
    # lets anything that reaches the worker choose what we say.
    #
    # The ordering is part of the contract's meaning rather than tidiness. The
    # row bounds the list at 32, and truncating an unordered set takes a
    # different 32 on each run, so two identical runs would produce receipts
    # that differ and neither could be compared byte for byte against the other
    # or against a fixture. Ascending by id is the order, stated here so nobody
    # substitutes insertion order later and breaks comparison quietly.
    admissible = sorted({rule_id for rule_id in (rule_ids or ())
                         if rule_id in catalog})[:MAX_RULE_IDS]

    return {
        "jsonrpc": "2.0",
        "id": request_id,                     # the ACTUAL id, its own JSON type
        "error": {
            "code": WITHHELD_CODE,
            "message": WITHHELD_MESSAGE,
            "data": {
                "reason_code": reason_code,
                "rule": rule,
                "budget": budget,
                "accepted": accepted,
                "status": status,
                "inspection_complete": inspection_complete,
                "inspected_utf8_bytes": _number(inspected_utf8_bytes,
                                                "inspected_utf8_bytes"),
                "observed_content_bytes": _number(observed_content_bytes,
                                                  "observed_content_bytes"),
                "elapsed_ms": _number(elapsed_ms, "elapsed_ms"),
                "rule_ids": admissible,
            },
        },
    }
