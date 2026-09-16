"""Turning an accepted worker result into the one reason the client is told.

T4.R3 maps the engine's vocabulary onto the wire's, and T4.R4 decides which
cause wins. The row that has already cost a run is T4.R4(7), and it is worth
stating before the code says it:

  PROHIBITED_SECRET iff the held message is a client to upstream `tools/call`
  REQUEST, never a notification and never a result and never a list, AND at
  least one finding id is in the ENGINE secret family `GLS-SD-*`. Otherwise
  PROHIBITED_CONTENT.

Both halves are load bearing and each one alone is a different bug. Dropping the
direction test labels G2-14, a client notification carrying GLS-SD-001, as a
secret exfiltration when it is not an outbound call at all. Dropping the family
test labels any high finding on an outbound call a secret. And the helper
credential lane, `GLS-FW-SEC-*`, deliberately does NOT qualify. It reads like a
secret rule to a human and is not in the engine secret family, so G2-16 settles
PROHIBITED_CONTENT. A check written as "looks like a credential rule" gets that
backwards, which is why the family is a prefix rather than a resemblance.

The paired G2-04 calibration measured the spike settling PROHIBITED_CONTENT with
`inspection_complete=false` for a COMPLETE engine finding. Both halves of that
were wrong and both are fixed here: the reason, and the completeness that the
harness had been deriving from whether anything was forwarded.
"""
from __future__ import annotations

from . import worker

# T4.R5's catalog, the subset this module can produce. Frozen for 0.6.0.
CLEAN = "CLEAN"
NO_FINDING_KNOWN_DETECTOR_GAP = "NO_FINDING_KNOWN_DETECTOR_GAP"
PROHIBITED_CONTENT = "PROHIBITED_CONTENT"
PROHIBITED_SECRET = "PROHIBITED_SECRET"
REVIEW_REQUIRED = "REVIEW_REQUIRED"
SCAN_EXCEPTION = "SCAN_EXCEPTION"
SCAN_DEADLINE = "SCAN_DEADLINE"
REQUEST_CANCELLED = "REQUEST_CANCELLED"

# The ENGINE secret family. Matched with the finding's `source`, never on the
# name alone, so a helper id that happens to look similar cannot qualify.
ENGINE_SECRET_PREFIX = "GLS-SD-"


def is_outbound_tool_call(held):
    """T4.R4(7)'s direction test, spelled out as the three things it excludes.

    `held` describes the message the finding is about: its direction, whether it
    is a request, and its method. A notification has no id and is not a request;
    a result travels the other way; `tools/list` is not a call.
    """
    return bool(
        held.get("direction") == "request"
        and held.get("is_request") is True
        and held.get("method") == "tools/call"
    )


def has_engine_secret_finding(findings):
    """The family test. Engine source AND the engine secret prefix.

    The PREFIX is what keeps the helper credential lane out: `GLS-FW-SEC-*`
    reads like a secret rule to a human but does not start with `GLS-SD-`, so
    G2-16 settles PROHIBITED_CONTENT on the prefix alone. A check written as
    "looks like a credential rule" would get that backwards, which is why the
    family is a prefix and not a resemblance.

    The SOURCE test guards something else, and I nearly wrote a comment claiming
    it guarded G2-16 until the mutation that removes it failed to flip G2-16 and
    flipped only one other case. What it actually guards is a HELPER reporting
    an engine-prefixed id. The helper lane is deterministic and separate, and a
    helper naming `GLS-SD-001` is not the engine having found it, so it must not
    buy the stronger reason. One check, one thing, stated as the thing it does.
    """
    return any(f.get("source") == worker.SOURCE_ENGINE
               and str(f.get("rule_id", "")).startswith(ENGINE_SECRET_PREFIX)
               for f in findings)


def finding_reason(held, findings):
    """T4.R4(7). Which of the two prohibition reasons this finding settles as."""
    if is_outbound_tool_call(held) and has_engine_secret_finding(findings):
        return PROHIBITED_SECRET
    return PROHIBITED_CONTENT


class Settlement:
    __slots__ = ("reason", "rule", "accepted", "status", "inspection_complete",
                 "rule_ids", "disposition", "detail")

    def __init__(self, reason, rule, *, accepted, status, inspection_complete,
                 rule_ids=(), disposition=None, detail=None):
        self.reason = reason
        self.rule = rule
        self.accepted = accepted
        self.status = status
        self.inspection_complete = inspection_complete
        self.rule_ids = list(rule_ids)
        self.disposition = disposition or reason
        self.detail = detail

    def as_receipt(self):
        return {"reason_code": self.reason, "rule": self.rule,
                "accepted": self.accepted, "status": self.status,
                "inspection_complete": self.inspection_complete,
                "rule_ids": self.rule_ids, "disposition": self.disposition,
                "detail": self.detail}

    def __repr__(self):
        return (f"<Settlement {self.rule}/{self.reason} "
                f"complete={self.inspection_complete}>")


# T407. The rule a RECORDED cause carries. Rule A makes an earlier fault
# terminal, which is right, and it was also settling every one of them as S3:
# the reason survived and the rule did not, which files a framing fault at the
# severity of a failed scan.
#
# The map follows the product rather than inventing a taxonomy. `pump._close`
# defaults to S5 and is called with that default for exactly the two framing
# faults, and names S3 explicitly everywhere else (OVERLOADED, and the protocol
# version the server offered). Anything not named here is S3, which keeps the
# default the conservative one.
_CAUSE_RULES = {
    "MALFORMED_UPSTREAM": "S5",
    "MALFORMED_CLIENT": "S5",
    REQUEST_CANCELLED: "S6",
}


def rule_for(reason):
    """The rule that belongs to a reason, wherever the reason came from."""
    return _CAUSE_RULES.get(reason, "S3")


def settle(result, *, held, held_content_bytes, helper_outcome="clean",
           independent_cause=None, known_detector_gap=False,
           cancellation_owned=False):
    """T4.R4(6b) through (9), for an ALREADY VALIDATED worker result.

    Validation is `worker.validate` and is deliberately a separate step: this
    function may assume the result is coherent, and giving it the job of
    deciding that too is how "not obviously bad" becomes a verdict.

    `independent_cause` is anything recorded for the item before the worker
    answered. It is passed in rather than looked up, because Rule A is about
    ORDER and only the caller holding the session knows the order.

    `cancellation_owned` says whether the CLIENT cancelled this request, and is
    passed in for the same reason: a worker reporting `cancelled` says only
    that its scan stopped, never who stopped it, and the tombstones that answer
    that live in the session. T406. Defaulting to False makes the quiet answer
    the conservative one -- an unexplained abort reads as a scan that did not
    happen rather than as a client who changed their mind.
    """
    if independent_cause is not None:
        # T4.R4 Rule A. An earlier fault is terminal, and the completion that
        # arrives afterwards does not get to relabel it.
        return Settlement(independent_cause, rule_for(independent_cause),
                          accepted=result["accepted"],
                          status=result["status"], inspection_complete=False,
                          detail="an independent cause was recorded first")

    findings = result["findings"]
    rule_ids = sorted({f["rule_id"] for f in findings})

    blocking = [f for f in findings
                if f["severity"] in worker.BLOCKING_SEVERITIES]
    if blocking and result["status"] == worker.STATUS_COMPLETE:
        # T4.R4(7). COMPLETE and TRUE, both of them. The calibration found the
        # spike reporting inspection_complete=false here, which said a scan that
        # ran to the end and found exactly what it was looking for had not
        # finished.
        return Settlement(finding_reason(held, findings), "S2",
                          accepted=True, status=worker.STATUS_COMPLETE,
                          inspection_complete=True, rule_ids=rule_ids)

    if result["status"] != worker.STATUS_COMPLETE:
        # T4.R4(6b). An accepted result that did not complete, with no
        # authorized hold explaining it, is S3 and its findings are PRESERVED.
        reason = {worker.STATUS_EXCEPTION: SCAN_EXCEPTION,
                  worker.STATUS_DEADLINE: SCAN_DEADLINE,
                  worker.STATUS_CANCELLED: REQUEST_CANCELLED,
                  }.get(result["status"], SCAN_EXCEPTION)
        # T406. S6 says the CLIENT withdrew the request, which says the bytes
        # were never in question. A worker that stopped on its own reached no
        # verdict about bytes that WERE in question, and that is S3. The worker
        # cannot tell the two apart, so an unowned cancellation is not one.
        if reason == REQUEST_CANCELLED and not cancellation_owned:
            reason = SCAN_EXCEPTION
        return Settlement(reason, rule_for(reason),
                          accepted=result["accepted"], status=result["status"],
                          inspection_complete=False, rule_ids=rule_ids)

    if result["decision"] == worker.DECISION_REVIEW or findings:
        # T4.R4(8). Complete, and either the engine asked for review or there
        # are findings below the blocking severities.
        return Settlement(REVIEW_REQUIRED, "S7", accepted=True,
                          status=worker.STATUS_COMPLETE,
                          inspection_complete=True, rule_ids=rule_ids)

    failed = worker.is_s1_eligible(
        result, held_content_bytes=held_content_bytes,
        helper_outcome=helper_outcome, independent_cause=None)
    if failed:
        # Anything accepted that is not S2 or S7 and is not fully S1 eligible is
        # S3, per T4.R2's cause 6b. "Nearly clean" is not a verdict.
        return Settlement(SCAN_EXCEPTION, "S3", accepted=result["accepted"],
                          status=result["status"], inspection_complete=False,
                          rule_ids=rule_ids, detail="; ".join(failed))

    # T4.R4(9). The one verdict that lets bytes through.
    #
    # The gap disposition is CHANNEL `message` ONLY, as the rule writes it. On
    # `api_response` it labels an ARRIVING result as a known published miss of
    # OURS -- a statement about our own coverage attached to something we never
    # claimed to cover.
    gap = known_detector_gap and result["binding"].get("channel") == "message"
    return Settlement(
        CLEAN, "S1", accepted=True, status=worker.STATUS_COMPLETE,
        inspection_complete=True,
        disposition=NO_FINDING_KNOWN_DETECTOR_GAP if gap else CLEAN)
