"""The hook's receipt rows as chained bodies (spec §1 + §5, T9 RULING 11 Q3).

AN ALLOWLIST, VALUE-CHECKED. Every field a chained hook body may carry is named
below with the grammar its value must meet. A field that is not named, or whose
value fails, is WITHHELD and its name is listed in `withheld`; a name that is
not itself a plain field name is only counted. A signed byte is permanent, so
the failure mode is "less evidence, said out loud", never "whatever arrived".

INTEGERS ONLY, FIXED HERE. `elapsed_ms` becomes `elapsed_us`; an age in
seconds is floored. The wire refuses floats and never rounds; the producer
does, once, at a named place.

THE ERROR'S CLASS NAME ONLY. An exception message may quote the value that
raised it, so `error` never reaches a chained body; the caller passes the class
names as `error_types`. That drop is the rule, so it is not listed as withheld.

`tool_name` and `session_id` are expected already through the firewall's
`sanitize_receipt_field`; the printable check here is the backstop.
"""
from __future__ import annotations

import re

_EVAL_ID = re.compile(r"\A[0-9a-f]{16}\Z")
_DIGEST = re.compile(r"\A[0-9a-f]{64}\Z")
_RULE_ID = re.compile(r"\AGLS-[A-Z0-9-]{1,60}\Z")      # proxy/receipts.py _RULE_ID
_TOKEN = re.compile(r"\A[a-z_]{1,32}\Z")
_CLASS_NAME = re.compile(r"\A[A-Za-z_][A-Za-z0-9_.]{0,63}\Z")
_TIMESTAMP = re.compile(r"\A[0-9T:.+\-Z]{1,40}\Z")
_CANARY_FP = re.compile(r"\Asha256:[0-9a-f]{8,64}\Z")
_FIELD_NAME = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")

DECISIONS = {"allow", "deny", "ask", "defer"}
LANES = {"deterministic", "fuzzy", "error"}
MAX_TEXT = 256
MAX_LIST = 64

# Carried by the envelope, or replaced by a checked field: never in the body.
_ENVELOPE = {"ts", "kind"}
_REPLACED = {"error", "elapsed_ms", "input_sha256_reason"}


def _text(value):
    return (isinstance(value, str) and 0 < len(value) <= MAX_TEXT
            and value.isprintable())


def _flag(value):
    return value is True


def _digest(value):
    return value is None or (isinstance(value, str) and bool(_DIGEST.match(value)))


def _match(pattern):
    return lambda value: isinstance(value, str) and bool(pattern.match(value))


def _one_of(allowed):
    return lambda value: isinstance(value, str) and value in allowed


_PAIRING = {
    "eval_id": _match(_EVAL_ID),
    "tool_name": _text,
    "session_id": _text,
    "input_sha256": _digest,
}

_DECISION = {
    **_PAIRING,
    "decision": _one_of(DECISIONS),
    "lane": _one_of(LANES),
    "rule_id": _match(_RULE_ID),
    "degraded": _flag,
    "fuzzy_lane": _flag,
    "pin_state_stale": _flag,
    "policy_state": _match(_TOKEN),
    "pin_source": _match(_TOKEN),
    "pin_reach": _match(_TOKEN),
    "pin_checked_at": _match(_TIMESTAMP),
}


def in_flight(row: dict) -> dict:
    return _body(row, _PAIRING)


def decision(row: dict, *, error_types=()) -> dict:
    body = _body(row, _DECISION)
    withheld = set(body.pop("withheld", []))

    ms = row.get("elapsed_ms")
    if isinstance(ms, (int, float)) and not isinstance(ms, bool) and 0 <= ms < 1e12:
        body["elapsed_us"] = int(round(ms * 1000))
    elif ms is not None:
        withheld.add("elapsed_ms")

    if "pin_state_age_s" in row:
        age = row["pin_state_age_s"]
        if age is None or (isinstance(age, (int, float)) and not isinstance(age, bool)
                           and 0 <= age < 1e12):
            body["pin_state_age_s"] = None if age is None else int(age)
        else:
            withheld.add("pin_state_age_s")

    if "cleared_canaries" in row:
        cleared = _canaries(row["cleared_canaries"])
        if cleared is None:
            withheld.add("cleared_canaries")
        else:
            body["cleared_canaries"] = cleared

    types = list(error_types)
    if types:
        if len(types) <= MAX_LIST and all(_match(_CLASS_NAME)(t) for t in types):
            body["error_types"] = types
        else:
            withheld.add("error_types")

    if withheld:
        body["withheld"] = sorted(withheld)
    return body


_HANDLED_BY_DECISION = {"pin_state_age_s", "cleared_canaries"}


def _body(row: dict, allowed: dict) -> dict:
    body, withheld, unnamed = {}, [], 0
    for key, value in row.items():
        if key in _ENVELOPE or key in _REPLACED:
            continue
        if allowed is _DECISION and key in _HANDLED_BY_DECISION:
            continue
        check = allowed.get(key)
        if check is not None and check(value):
            body[key] = value
        elif isinstance(key, str) and _FIELD_NAME.match(key):
            withheld.append(key)
        else:
            unnamed += 1
    if row.get("input_sha256_reason") == "unencodable" and row.get("input_sha256") is None:
        body["input_digest"] = "UNENCODABLE"
    if withheld:
        body["withheld"] = sorted(withheld)
    if unnamed:
        body["withheld_unnamed"] = unnamed
    return body


def _canaries(value):
    if not isinstance(value, list) or len(value) > MAX_LIST:
        return None
    out = []
    for entry in value:
        if not (isinstance(entry, dict) and _match(_RULE_ID)(entry.get("rule_id"))
                and _match(_CANARY_FP)(entry.get("fingerprint"))):
            return None
        out.append({"rule_id": entry["rule_id"], "fingerprint": entry["fingerprint"]})
    return out
