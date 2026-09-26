"""T4.R3, the engine's vocabulary onto the wire's.

Written against `tests/test_proxy_inspection.py`, committed first from the rows.

Small, and the two ways it goes wrong are both quiet.

It is a CONSTRUCTOR, never a copy. The engine names the bytes it matched in
`matched_text` and keeps the whole message in `raw_input` and
`normalized_input`, which is the most useful thing in the result for a human
and the most dangerous thing to forward, because every road out of a worker
result ends at the client through T4.R7 or at the receipt log through T9.R2.
Each finding is rebuilt from three named fields, so a field nobody named cannot
travel and a field the engine adds next release cannot either.

And T3.R1 decides what the engine is given: every coverage leaf joined by
newlines. Not the raw frame. Handing it the frame scans our own envelope,
charges protocol scalars against a content budget that excludes them, and only
misses nothing by accident. Object KEYS are coverage leaves, which is the part
that matters: an injection sitting in a key is inspected here or nowhere.

Fail closed is the direction throughout. A scan that raised did not look, so it
is `exception` and never `allow`, because allow is the engine's word for having
looked.

WHAT THIS IS NOT, IN THE DEFAULT MODE: the T4 worker PROCESS. By default
(`--worker inprocess`) the engine runs in this process, so T8.R4's kill on
deadline and T8.R7's worker stdout bound do not apply to it and a scan that
hangs stalls the session rather than being killed at 2,000 ms. The session
holds the message throughout, so nothing is released by the stall, but the
bound is not enforced on that path and saying otherwise would be the kind of
claim this lane exists to refuse. `--worker process` runs this same function
in a child (`worker_process.ProcessScan`) where both bounds ARE enforced; it is
opt-in, and the sentence above stays true of the default.
"""
from __future__ import annotations

from . import selector, worker

STATUS_COMPLETE = "complete"
STATUS_INCOMPLETE = "incomplete"
STATUS_EXCEPTION = "exception"
STATUS_DEADLINE = "deadline"      # mirrors worker.STATUS_DEADLINE, like its neighbours

DECISION_ALLOW = "allow"
DECISION_REVIEW = "review"

SOURCE_ENGINE = "engine"

# The three fields a finding is allowed to have on the wire. Named here rather
# than subtracted from the engine's, because a denylist of the engine's fields
# is only correct until the engine grows one.
FINDING_FIELDS = ("rule_id", "severity", "source")

_engine = None


def default_engine():
    """One engine per process. Loading the pattern set per message would put a
    cold start inside T8.R4's inspection clock on every frame."""
    global _engine
    if _engine is None:
        from ..engine import SunglassesEngine
        _engine = SunglassesEngine()
    return _engine


# T4.R6's helper lane pins, which are string literals at their call sites in
# firewall.py rather than a collection. Named here so the catalog ENUMERATES
# them. A prefix test would accept any id shaped like one of these, and a
# catalog that accepts a shape is not a catalog.
HELPER_PIN_IDS = ("GLS-FW-PIN-TOFU", "GLS-FW-PIN-MISMATCH", "GLS-FW-PIN-DRIFT")


def engine_catalog():
    """T4.R6's pinned engine ids: the pattern set AND the mechanism lane.

    Both, and the second half is the part that was missing. The mechanism rules
    are eleven ids the engine can return like any other, and 1,546 + 11 is
    exactly the 1,557 the row names. Leaving them out did not let anything
    through, because an id outside the catalog is refused and the message is
    withheld, but it withheld them as SCAN_EXCEPTION, which says the scan could
    not be believed rather than that the scan found something. Every mechanism
    detection in the product would have carried the wrong reason and read as an
    instrument fault.
    """
    from .. import mechanisms, patterns
    ids = {str(pattern["id"]) for pattern in patterns.PATTERNS
           if isinstance(pattern, dict) and pattern.get("id")}
    ids |= {str(rule["id"]) for rule in mechanisms.MECHANISM_PATTERNS
            if isinstance(rule, dict) and rule.get("id")}
    return frozenset(ids)


def helper_catalog():
    """T4.R6's enrolled deterministic helper lane, enumerated from firewall.py."""
    from .. import firewall
    return frozenset({str(rule.id) for rule in firewall.SECRET_RULES}
                     | set(HELPER_PIN_IDS))


def trusted_catalog():
    """T4.R6 in full: engine ids union helper lane ids."""
    return engine_catalog() | helper_catalog()


def scanner_input(params):
    """T3.R1. Every coverage leaf, in document order, joined by newlines.

    The join is ours and is not counted against the content budget, which is
    why `content_bytes` is measured separately rather than as the length of
    this string.
    """
    return "\n".join(value for _pointer, value in selector.coverage_leaves(params))


def scan(params, *, channel, binding, content_bytes, engine=None):
    """One held message to one T4.R1 worker result."""
    engine = engine if engine is not None else default_engine()
    text = scanner_input(params)
    inspected = len(text.encode("utf-8", "surrogatepass"))
    # The join is ours, so the inspected count never exceeds what the peer
    # actually sent. Reporting our separators as inspected bytes would break
    # T4.R2's inspected <= observed <= held on any message with two leaves.
    inspected = min(inspected, content_bytes)

    try:
        result = engine.scan(text, channel=channel)
    except TimeoutError:
        # T4.R3 names this one separately: an engine TIMEOUT is `deadline`, not
        # `exception`. Both landed in the generic branch, so a scan that ran out
        # of time recorded "the scanner broke" for "the scanner did not finish
        # in the budget" -- different facts, and only one is a reason to
        # distrust the scanner.
        return worker.LocalFault(_result(
            binding, accepted=False, status=STATUS_DEADLINE,
            inspection_complete=False, decision=DECISION_REVIEW,
            inspected=0, observed=content_bytes, elapsed=0, findings=()))
    except Exception:
        # T4.R3. A scan that raised did not look. `allow` is the engine's word
        # for having looked and found nothing, and the exception text is
        # peer-adjacent prose that never reaches a result.
        return worker.LocalFault(_result(
            binding, accepted=False, status=STATUS_EXCEPTION,
            inspection_complete=False, decision=DECISION_REVIEW,
            inspected=0, observed=content_bytes, elapsed=0, findings=()))

    truncated = bool(getattr(result, "truncated", False)) or not bool(
        getattr(result, "extraction_complete", True))
    # What the engine says it READ, not what we handed it. A truncated scan
    # that reports the whole message as inspected overstates the inspection by
    # exactly the amount nobody looked at, which is the fault the paired
    # calibration caught arriving from the other direction.
    scanned = getattr(result, "bytes_scanned", None)
    if isinstance(scanned, int) and not isinstance(scanned, bool) and scanned >= 0:
        inspected = min(inspected, scanned)
    return _result(
        binding,
        accepted=True,
        status=STATUS_INCOMPLETE if truncated else STATUS_COMPLETE,
        inspection_complete=not truncated,
        decision=getattr(result, "decision", DECISION_REVIEW),
        inspected=inspected,
        observed=content_bytes,
        elapsed=int(getattr(result, "latency_ms", 0) or 0),
        findings=_findings(getattr(result, "findings", ()) or ()))


def _findings(raw):
    """Three named fields, built, never copied."""
    built = []
    for finding in raw:
        if not isinstance(finding, dict):
            continue
        rule_id = finding.get("id") or finding.get("rule_id")
        if not rule_id:
            continue
        built.append({"rule_id": str(rule_id),
                      "severity": str(finding.get("severity", "info")),
                      "source": SOURCE_ENGINE})
    return built


def _result(binding, *, accepted, status, inspection_complete, decision,
            inspected, observed, elapsed, findings):
    if decision not in worker.DECISIONS:
        decision = DECISION_REVIEW
    return {
        "binding": dict(binding),
        "accepted": accepted,
        "status": status,
        "inspection_complete": inspection_complete,
        "decision": decision,
        "inspected_utf8_bytes": inspected,
        "observed_content_bytes": observed,
        "elapsed_ms": elapsed,
        "findings": list(findings),
    }
