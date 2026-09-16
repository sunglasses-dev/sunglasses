"""What the scanner said, checked before any of it is believed.

T4.R1 fixes the worker's one line of stdout and T4.R2 fixes what makes it
acceptable. The reason T4.R2 is as long as it is: almost every field can be
wrong in a way that reads as a pass.

The spike this replaces decided from the worker's EXIT CODE and never read the
result, so a payload the engine BLOCKED was forwarded to the model unchanged.
Fixing that by reading the JSON is necessary and not sufficient, because a
result can parse perfectly and still be incoherent, and the incoherent shapes
are exactly the ones that look clean:

  `decision: "allow"` beside a critical finding;
  `inspection_complete: true` with `status` anything but complete;
  counters claiming more was inspected than was ever observed;
  `accepted: false` with a status that suggests it finished;
  a rule id that is not in the trusted catalog, which is how a worker invents
  the authority to clear something.

So S1 ELIGIBILITY is written as an explicit CONJUNCTION, per T4.R2, and anything
that is not S1, S2 or S7 is S3. "Not obviously bad" is not a verdict.
"""
from __future__ import annotations

# T4.R1's enums. Frozen for 0.6.0.
STATUS_COMPLETE = "complete"
STATUS_INCOMPLETE = "incomplete"
STATUS_EXCEPTION = "exception"
STATUS_DEADLINE = "deadline"
STATUS_CANCELLED = "cancelled"
STATUS_NOT_RUN = "not_run"
STATUSES = frozenset({STATUS_COMPLETE, STATUS_INCOMPLETE, STATUS_EXCEPTION,
                      STATUS_DEADLINE, STATUS_CANCELLED, STATUS_NOT_RUN})

DECISION_ALLOW = "allow"
DECISION_BLOCK = "block"
DECISION_REVIEW = "review"
DECISIONS = frozenset({DECISION_ALLOW, DECISION_BLOCK, DECISION_REVIEW})

SOURCE_ENGINE = "engine"
SOURCE_HELPER = "helper"
SOURCES = frozenset({SOURCE_ENGINE, SOURCE_HELPER})

SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
BLOCKING_SEVERITIES = frozenset({"high", "critical"})

_BINDING_FIELDS = ("digest", "channel", "generation", "invocation_token")
_COUNTERS = ("inspected_utf8_bytes", "observed_content_bytes", "elapsed_ms")
_BYTE_COUNTERS = ("inspected_utf8_bytes", "observed_content_bytes")


class Invalid(ValueError):
    """The worker's result cannot be believed. Always S3, never a verdict."""


def _typed(value, kind):
    """`isinstance` with the bool hole closed, for the two kinds actually used.

    The contract says a string "false" is invalid where a bool is required, and
    the same trap runs the other way: `isinstance(True, int)` is True, so a bool
    passes a naive number check and `inspected_utf8_bytes: True` would read as 1.

    An earlier version carried an `int` branch as well. Nothing called it, and a
    mutation that removed its bool guard killed no test, which is how I found
    out. Dead code in a validator is a place for a future bug to hide behind a
    passing suite, so it is gone rather than left for a caller that may never
    arrive.
    """
    if kind is bool:
        return isinstance(value, bool)
    if kind is float:
        return (isinstance(value, (int, float))
                and not isinstance(value, bool))
    if kind is int:
        # The int branch is BACK, and the docstring above says it was removed
        # for being dead. It is not dead now: T4.R1 declares the two byte
        # counters as integers and AT01 caught the validator taking 9.5 for
        # one. The bool guard is the same trap in the same place -- True is an
        # int -- and AT07 already drives True and False through every counter,
        # so the guard has a control this time.
        return isinstance(value, int) and not isinstance(value, bool)
    raise AssertionError(f"_typed has no rule for {kind!r}")


def validate(result, *, binding, held_content_bytes, catalog):
    """T4.R2. Return the result, or raise Invalid naming the first thing wrong.

    `catalog` is T4.R6's trusted id set. A worker reporting an id outside it has
    either found something with a rule nobody pinned or invented one, and both
    are the same fact about how much we can rely on the answer.
    """
    if not isinstance(result, dict):
        raise Invalid(f"worker result is {type(result).__name__}, not an object")

    got = result.get("binding")
    if not isinstance(got, dict):
        raise Invalid("worker result has no binding")
    for field in _BINDING_FIELDS:
        if field not in got:
            raise Invalid(f"binding is missing {field}")
        if type(got[field]) is not type(binding[field]) or got[field] != binding[field]:
            # A result bound to a different message is not this item's answer,
            # however well formed it is. Accepting it settles one message with
            # another message's scan.
            raise Invalid(
                f"binding {field} is {got[field]!r} and this item's is "
                f"{binding[field]!r}; the result belongs to another invocation")

    if not _typed(result.get("accepted"), bool):
        raise Invalid(f"accepted is {result.get('accepted')!r}, not a boolean")
    status = result.get("status")
    if not isinstance(status, str) or status not in STATUSES:
        raise Invalid(f"status {status!r} is not one of {sorted(STATUSES)}")
    if not _typed(result.get("inspection_complete"), bool):
        raise Invalid(
            f"inspection_complete is {result.get('inspection_complete')!r}, "
            f"not a boolean")
    decision = result.get("decision")
    if not isinstance(decision, str) or decision not in DECISIONS:
        raise Invalid(f"decision {decision!r} is not one of {sorted(DECISIONS)}")

    for counter in _COUNTERS:
        value = result.get(counter)
        if counter in _BYTE_COUNTERS:
            # T4.R1 declares these `int>=0`. A float passed the number check and
            # 9.5 bytes is a description of something that did not happen -- and
            # `inspected <= observed <= held` then compares fictions. elapsed_ms
            # is declared `number`, so it keeps the wider check.
            if not _typed(value, int):
                raise Invalid(f"{counter} is {value!r}, not an integer")
        elif not _typed(value, float):
            raise Invalid(f"{counter} is {value!r}, not a number")
        if value < 0:
            raise Invalid(f"{counter} is negative")
        if value != value or value in (float("inf"), float("-inf")):
            raise Invalid(f"{counter} is not finite")

    findings = result.get("findings")
    if not isinstance(findings, list):
        raise Invalid("findings is not a list")
    for finding in findings:
        if not isinstance(finding, dict):
            raise Invalid("a finding is not an object")
        for field in ("rule_id", "severity", "source"):
            if field not in finding:
                raise Invalid(f"a finding is missing {field}")
        # AT11. `x in frozenset` RAISES TypeError when x is unhashable, and
        # TypeError is not Invalid: it goes straight past the caller's
        # `except Invalid` and out of the reader. The peer chooses these bytes,
        # so a list where a string belongs is a reachable state, not a
        # theoretical one. A non-string is refused before anything hashes it.
        if not isinstance(finding["severity"], str) or \
                finding["severity"] not in SEVERITIES:
            raise Invalid(f"severity {finding['severity']!r} is not known")
        if not isinstance(finding["source"], str) or \
                finding["source"] not in SOURCES:
            raise Invalid(f"source {finding['source']!r} is not known")
        if not isinstance(finding["rule_id"], str) or finding["rule_id"] not in catalog:
            # T4.R6. A worker cannot confer authority on itself by naming a rule.
            raise Invalid(
                f"rule id {finding['rule_id']!r} is not in the trusted catalog")

    inspected = result["inspected_utf8_bytes"]
    observed = result["observed_content_bytes"]
    if not inspected <= observed <= held_content_bytes:
        raise Invalid(
            f"counters are incoherent: inspected {inspected}, observed "
            f"{observed}, held {held_content_bytes}; inspected must not exceed "
            f"observed and observed must not exceed what was held")

    blocking = [f for f in findings if f["severity"] in BLOCKING_SEVERITIES]
    if decision == DECISION_ALLOW and blocking:
        # The shape that matters most. A worker that found something critical
        # and cleared it anyway is not a clean scan with a stray note attached.
        raise Invalid(
            f"decision is allow with {len(blocking)} high or critical "
            f"finding(s); a result that clears what it found is not usable")

    if result["inspection_complete"] and status != STATUS_COMPLETE:
        raise Invalid(
            f"inspection_complete is true with status {status!r}; only a "
            f"complete scan can claim it finished")
    if status == STATUS_COMPLETE and not result["inspection_complete"]:
        # T4.R2, the other direction, and it was the one missing. A result that
        # says the scan RAN TO THE END while also saying the inspection did not
        # finish is not a verdict; accepting it let the settlement report
        # inspection_complete TRUE for it, inventing the completeness the
        # worker itself had denied.
        raise Invalid(
            "status is complete with inspection_complete false; a scan cannot "
            "have finished and not finished")
    if not result["accepted"]:
        raise Invalid(
            f"accepted is false with status {status!r}; an unaccepted result is "
            f"not a verdict whatever it claims")
    return result


def is_s1_eligible(result, *, held_content_bytes, helper_outcome,
                   independent_cause):
    """T4.R2's S1 conjunction, spelled out, every term required.

    Written as an explicit AND of named terms rather than as a chain of early
    returns, because S1 is the one verdict that lets bytes through and the way
    that goes wrong is a term quietly not being checked. Returns the list of
    terms that FAILED, so a caller can say why rather than only that it did.
    """
    failed = []
    if result.get("accepted") is not True:
        failed.append("accepted is not true")
    if result.get("status") != STATUS_COMPLETE:
        failed.append(f"status is {result.get('status')!r}, not complete")
    if result.get("inspection_complete") is not True:
        failed.append("inspection_complete is not true")
    if not (result.get("inspected_utf8_bytes")
            == result.get("observed_content_bytes") == held_content_bytes):
        failed.append(
            f"inspected {result.get('inspected_utf8_bytes')}, observed "
            f"{result.get('observed_content_bytes')}, held "
            f"{held_content_bytes}; S1 requires all three equal")
    if result.get("decision") != DECISION_ALLOW:
        failed.append(f"decision is {result.get('decision')!r}, not allow")
    if result.get("findings"):
        failed.append(f"{len(result['findings'])} finding(s) present")
    if helper_outcome not in ("clean", "not applicable"):
        failed.append(f"helper outcome is {helper_outcome!r}")
    if independent_cause is not None:
        failed.append(f"an independent cause is recorded: {independent_cause}")
    return failed
