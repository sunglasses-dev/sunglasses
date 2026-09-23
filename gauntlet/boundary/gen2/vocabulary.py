"""ASTRA's worker-result vocabulary -> the product's, as ONE checked table.

T9 RULING 2026-09-23: map, do not reissue. ASTRA's cases are the SOURCE, the
product's `sunglasses/proxy/worker.py validate` vocabulary is the TARGET, and
this table is the contract between them. Measured before it existed: the
delivery's UNFAULTED base result was Invalid on the product (it names no
`observed_content_bytes`, calls a finding's id `id`, puts the binding at the top
level, says `quarantine`), so every shape was rejected before its own fault was
ever looked at. A stimulus that is refused for its spelling measures nothing.

THE TABLE MAPS NAMES, NEVER VALUES THAT CARRY THE FAULT. `inspection_complete:
"false"` stays the string "false"; `accepted` is not added to a result that
omits it. Only three things are ever SUPPLIED, each said here and nowhere else:
  - binding fields the delivery leaves as BIND_AT_SCAN_STARTED or does not name
    at all: from the actual invocation (the delivery's own placeholder says so)
  - `observed_content_bytes` and `elapsed_ms`: the delivery names neither in any
    shape, the product requires both, and both are observations of the run
  - a finding's `source`: the lane the PRODUCT catalog gives that rule id
    (validate already refuses a source that disagrees with the catalog)

AN UNMAPPED NAME ABORTS, naming itself. A key, a decision value or a finding
field this table has not seen is a delivery the contract does not cover, and a
silent pass-through would hand the product a shape nobody reviewed.
"""
from __future__ import annotations

PLACEHOLDER = "BIND_AT_SCAN_STARTED"

# delivery top-level key -> ("field", product name) | ("binding", product binding
# field) | ("drop", reason). A drop is a MAPPING to nothing, with its reason, not
# an omission.
TOP_LEVEL = {
    "accepted": ("field", "accepted"),
    "status": ("field", "status"),
    "inspection_complete": ("field", "inspection_complete"),
    "decision": ("field", "decision"),
    "findings": ("field", "findings"),
    "inspected_utf8_bytes": ("field", "inspected_utf8_bytes"),
    "input_sha256": ("binding", "digest"),
    "channel": ("binding", "channel"),
    "invocation_id": ("binding", "invocation_token"),
    "review_required": ("drop", "the product expresses review only through "
                                "decision=review (quarantine -> review below); "
                                "it has no separate flag to carry"),
}

# decision values. `quarantine` is ASTRA's word for the product's `review`.
DECISION = {"allow": "allow", "block": "block", "review": "review",
            "quarantine": "review"}

# delivery finding key -> product finding key
FINDING = {"id": "rule_id", "severity": "severity"}

# delivery outputs that are not results but instructions to the worker.
DIRECTIVE_KEYS = frozenset({"mode"})

# Supplied from the run, never from the delivery (see the module docstring).
SUPPLIED = ("observed_content_bytes", "elapsed_ms")


class UnmappedName(Exception):
    """The delivery used a name this table does not cover."""

    def __init__(self, where, name):
        self.where, self.name = where, name
        super().__init__(
            f"{where}: {name!r} is not in the delivery->product table "
            "(gen2/vocabulary.py). Add it with a reason, or the run is not "
            "about the shape ASTRA delivered.")


class Directive(Exception):
    """The delivered output is an instruction (run the normal engine), not a result."""


def is_directive(delivered: dict) -> bool:
    return isinstance(delivered, dict) and bool(DIRECTIVE_KEYS & set(delivered))


def map_result(delivered: dict, *, binding: dict, observed_content_bytes: int,
               elapsed_ms: float, lanes: dict) -> dict:
    """ASTRA's result, in the product's vocabulary, with its fault intact.

    `binding` is the actual invocation's {digest, channel, generation,
    invocation_token}. `lanes` maps a product rule id to its source lane.
    """
    if is_directive(delivered):
        raise Directive(f"directive, not a result: {sorted(delivered)}")
    out: dict = {}
    child_binding = dict(binding)
    for key, value in delivered.items():
        if key not in TOP_LEVEL:
            raise UnmappedName("result key", key)
        kind, target = TOP_LEVEL[key]
        if kind == "drop":
            continue
        if kind == "binding":
            if value != PLACEHOLDER:
                child_binding[target] = value
            continue
        if key == "decision":
            if not isinstance(value, str) or value not in DECISION:
                raise UnmappedName("decision value", value)
            value = DECISION[value]
        elif key == "findings":
            value = [_finding(f, lanes) for f in value] if isinstance(value, list) else value
        out[target] = value
    out["binding"] = child_binding
    out["observed_content_bytes"] = observed_content_bytes
    out["elapsed_ms"] = elapsed_ms
    return out


def _finding(delivered, lanes):
    if not isinstance(delivered, dict):
        return delivered
    mapped = {}
    for key, value in delivered.items():
        if key not in FINDING:
            raise UnmappedName("finding key", key)
        mapped[FINDING[key]] = value
    rule = mapped.get("rule_id")
    if rule not in lanes:
        raise UnmappedName("finding rule id (no product lane)", rule)
    mapped["source"] = lanes[rule]
    return mapped
