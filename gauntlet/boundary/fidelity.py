"""Did the experiment we designed actually run?

ASTRA's exam of run 28c39e0 graded 20 of 27 rows INVALID, and almost all of
them for the same reason: the stimulus never reached the thing under test. The
one that mattered most was G2-04, which this harness reported as a REAL DETECTOR
GAP. It was not. The driver named the tool and the path and never passed the
`content` argument at all, so the model called `write_file` with an empty
string: `request.json` specifies 21 content bytes, the actual call carried 0,
and the proxy dutifully inspected 161 bytes of path plus nothing and found
nothing to report. A detector cannot fail to find a secret that was never sent.
The same omission emptied G2-05 and G2-12.

The lesson is not "pass the content argument". It is that a candidate result is
meaningless until the stimulus is PROVEN, and proving it is not the grader's job
because by then the bytes are gone. So fidelity is checked at INGRESS, against
`request.json`, per argument leaf, by length and digest and type, and a row that
fails it terminates INVALID with a named reason BEFORE anything scores it.

A mismatch here is never a finding about the product. It is a finding about us.
"""
import hashlib
import json

# Canonical reasons. A row that ends INVALID names exactly one of these, so a
# reader never has to infer why an experiment did not happen.
OPERATION_NOT_INVOKED = "OPERATION_NOT_INVOKED"
OPERATION_MISMATCH = "OPERATION_MISMATCH"
METHOD_MISMATCH = "METHOD_MISMATCH"
ARGUMENT_MISSING = "ARGUMENT_MISSING"
ARGUMENT_EXTRA = "ARGUMENT_EXTRA"
ARGUMENT_TYPE_MISMATCH = "ARGUMENT_TYPE_MISMATCH"
ARGUMENT_VALUE_MISMATCH = "ARGUMENT_VALUE_MISMATCH"
STIMULUS_EXACT = "STIMULUS_EXACT"


def normalise_tool_name(name):
    """`write_file` and `mcp__fs__write_file` are the same operation.

    The package names the tool as the SERVER exposes it; the client names it as
    the model sees it, prefixed with the server it was routed through. Comparing
    the two raw would fail every correct row, and quietly comparing only the
    suffix would let a call routed through a DIFFERENT server pass as the same
    experiment. So the prefix is stripped and returned, and the caller records
    which server it was, rather than discarding it.
    """
    if name is None:
        return None, None
    if name.startswith("mcp__"):
        rest = name[len("mcp__"):]
        server, _, tool = rest.partition("__")
        if tool:
            return tool, server
    return name, None


def _encode(value):
    """The bytes a leaf really is, so `""` and a missing key are not the same.

    JSON gives us str, int, float, bool and None as leaves. Digesting the JSON
    encoding rather than `str(value)` keeps `1` and `"1"` distinct, which is
    what "typed values" in the work order asks for, and it keeps the digest
    stable for anything that is not a string.
    """
    if isinstance(value, str):
        return value.encode("utf-8")
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def leaf_digest(value):
    raw = _encode(value)
    return {"type": type(value).__name__, "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def flatten(value, prefix=""):
    """Every leaf of the argument tree, keyed by its dotted provenance.

    Provenance rather than a flat name because `arguments.content` and
    `arguments.metadata.content` are different leaves and a gate that conflated
    them would pass a call that wrote the right bytes into the wrong field.
    """
    # AN EMPTY CONTAINER IS STILL A LEAF. Recursing into `{}` or `[]` produced
    # no entries at all, so an empty object replaced by an empty list left both
    # sides with nothing to compare and the call passed as exact. The container
    # itself is the value there, and `{}` and `[]` are different values.
    if isinstance(value, dict):
        if not value:
            return {prefix: value}
        out = {}
        for key, sub in value.items():
            out.update(flatten(sub, f"{prefix}.{key}" if prefix else str(key)))
        return out
    if isinstance(value, list):
        if not value:
            return {prefix: value}
        out = {}
        for index, sub in enumerate(value):
            out.update(flatten(sub, f"{prefix}[{index}]"))
        return out
    return {prefix: value}


class Fidelity:
    """The verdict, and everything a stranger needs to check it."""

    def __init__(self, exact, reason, differences, intended, actual):
        self.exact, self.reason = exact, reason
        self.differences = differences
        self.intended, self.actual = intended, actual

    def __bool__(self):
        return self.exact

    def as_receipt(self):
        return {"stimulus_exact": self.exact, "reason": self.reason,
                "differences": self.differences,
                "intended_argument_bytes": self.intended,
                "actual_argument_bytes": self.actual}

    def __repr__(self):
        return f"<Fidelity {self.reason} {len(self.differences)} difference(s)>"


# The one server this harness mounts. `mcp_config` names it `fs`, so a call
# arriving through anything else went somewhere else, whatever the tool was
# called. Callers with a second route pass their own set.
DEFAULT_ROUTES = frozenset({"fs"})


def compare(intended_request, actual_call, *, allowed_routes=DEFAULT_ROUTES):
    """Compare the call that ARRIVED against the call `request.json` specifies.

    `intended_request` is the package's request object (`params.name`,
    `params.arguments`). `actual_call` is what was observed at ingress, as
    `{"name": ..., "arguments": {...}}`, or None when no qualifying call was
    made at all, which is its own reason rather than a silent zero.
    """
    intended_params = intended_request.get("params", {})
    intended_method = intended_request.get("method", "tools/call")
    intended_name = intended_params.get("name")
    intended_args = flatten(intended_params.get("arguments", {}), "params.arguments")
    intended_digests = {k: leaf_digest(v) for k, v in intended_args.items()}

    if actual_call is None:
        return Fidelity(False, OPERATION_NOT_INVOKED,
                        [{"reason": OPERATION_NOT_INVOKED,
                          "detail": f"no call to {intended_name!r} was observed "
                                    f"at ingress"}],
                        intended_digests, {})

    actual_name, routed_via = normalise_tool_name(actual_call.get("name"))
    actual_method = actual_call.get("method", "tools/call")
    actual_args = flatten(actual_call.get("arguments", {}), "params.arguments")
    actual_digests = {k: leaf_digest(v) for k, v in actual_args.items()}

    differences = []
    # The METHOD before the name. G2-06 declares `tools/list`, which has no tool
    # name at all, and the driver answered it with a `tools/call` to
    # `read_text_file`. Comparing names alone would call that a name mismatch;
    # it is a different RPC, and the descriptor surface the scenario exists to
    # test was never requested.
    if actual_method != intended_method:
        differences.append({"reason": METHOD_MISMATCH, "leaf": "method",
                            "intended": intended_method, "actual": actual_method,
                            "detail": f"the scenario's {intended_method} was "
                                      f"answered with {actual_method}"})
    # The operation first: the right bytes sent through the wrong operation is
    # a different experiment, not a near miss. G2-06 defaulted a `tools/list`
    # scenario to `read_text_file` and was graded as a result-content test.
    if actual_name != intended_name:
        differences.append({"reason": OPERATION_MISMATCH, "leaf": "params.name",
                            "intended": intended_name, "actual": actual_name,
                            "routed_via": routed_via})
    # THE ROUTE IS PART OF THE IDENTITY. `normalise_tool_name` already returned
    # which server the call came through, and nothing compared it, so a call to
    # the right tool with the right arguments through a DIFFERENT server passed
    # as the same experiment. Stripping the prefix and then ignoring what was
    # stripped is the same as never having it.
    elif routed_via is not None and routed_via not in allowed_routes:
        differences.append({"reason": OPERATION_MISMATCH, "leaf": "params.name",
                            "intended": intended_name, "actual": actual_call.get("name"),
                            "routed_via": routed_via,
                            "detail": f"the tool matches but the call arrived through "
                                      f"{routed_via!r}, not {sorted(allowed_routes)}"})

    for leaf in sorted(set(intended_digests) | set(actual_digests)):
        want, got = intended_digests.get(leaf), actual_digests.get(leaf)
        if got is None:
            differences.append({"reason": ARGUMENT_MISSING, "leaf": leaf,
                                "intended": want, "actual": None,
                                "detail": f"{want['bytes']} intended bytes were "
                                          f"never submitted"})
        elif want is None:
            differences.append({"reason": ARGUMENT_EXTRA, "leaf": leaf,
                                "intended": None, "actual": got})
        elif want["type"] != got["type"]:
            differences.append({"reason": ARGUMENT_TYPE_MISMATCH, "leaf": leaf,
                                "intended": want, "actual": got})
        elif want["sha256"] != got["sha256"]:
            differences.append({"reason": ARGUMENT_VALUE_MISMATCH, "leaf": leaf,
                                "intended": want, "actual": got,
                                "detail": f"{want['bytes']} intended bytes, "
                                          f"{got['bytes']} submitted"})

    if not differences:
        return Fidelity(True, STIMULUS_EXACT, [], intended_digests, actual_digests)
    # One named reason for the row, and it is the FIRST difference in a fixed
    # order of severity rather than whichever one sorted first: a row that both
    # used the wrong operation and dropped an argument is an operation problem.
    order = [METHOD_MISMATCH, OPERATION_MISMATCH, ARGUMENT_MISSING,
             ARGUMENT_TYPE_MISMATCH, ARGUMENT_VALUE_MISMATCH, ARGUMENT_EXTRA]
    reason = min((d["reason"] for d in differences), key=order.index)
    return Fidelity(False, reason, differences, intended_digests, actual_digests)
