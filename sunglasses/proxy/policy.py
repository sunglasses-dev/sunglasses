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


# T7.R1/T7.R2. Which rule a recorded cause carries. Protocol faults are S5 and
# nothing else is: the structural and resource breaches are explicitly NOT S5
# per T7.R1, and cancellation and approval keep their own rules because those
# are what actually happened to the item.
# Named as literals because these causes are recorded by the SESSION, not
# produced by this module, so they are not in the subset above; T4.R5 owns the
# catalog they come from.
_PROTOCOL_CAUSES = frozenset({"MALFORMED_CLIENT", "MALFORMED_UPSTREAM",
                              "UNSUPPORTED_PROTOCOL"})
_CAUSE_RULES = {REQUEST_CANCELLED: "S6", "APPROVAL_REQUIRED": "S4"}


def rule_for_cause(cause):
    """The rule that belongs to a cause recorded before the worker answered."""
    if cause in _PROTOCOL_CAUSES:
        return "S5"
    return _CAUSE_RULES.get(cause, "S3")


def settle(result, *, held, held_content_bytes, helper_outcome="clean",
           independent_cause=None, known_detector_gap=False):
    """T4.R4(6b) through (9), for an ALREADY VALIDATED worker result.

    Validation is `worker.validate` and is deliberately a separate step: this
    function may assume the result is coherent, and giving it the job of
    deciding that too is how "not obviously bad" becomes a verdict.

    `independent_cause` is anything recorded for the item before the worker
    answered. It is passed in rather than looked up, because Rule A is about
    ORDER and only the caller holding the session knows the order.
    """
    if independent_cause is not None:
        # T4.R4 Rule A. An earlier fault is terminal, and the completion that
        # arrives afterwards does not get to relabel it.
        #
        # THE RULE TRAVELS WITH THE CAUSE. This returned a hardcoded S3, so an
        # item already settled for a PROTOCOL fault came back out as a scan
        # fault: T7.R2 says each pending item settles with the first recorded
        # cause AND its rule -- S5 for protocol, S3 for resource or deadline,
        # S6 or S4 where that was what happened. The reason survived and the
        # rule did not, which reads in a receipt as the wrong kind of thing
        # having gone wrong, and S5 is the one that means the wire is no longer
        # trustworthy.
        return Settlement(independent_cause, rule_for_cause(independent_cause),
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
        return Settlement(reason, "S6" if reason == REQUEST_CANCELLED else "S3",
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
    # The gap disposition is CHANNEL `message` ONLY, as the rule writes it. It
    # fired wherever the flag was set, including `api_response`, which labels
    # an ARRIVING result as a known published miss of OURS -- a statement about
    # our own detector coverage attached to something we never claimed to
    # cover. An S1 on any other channel is an ordinary CLEAN.
    gap = known_detector_gap and result["binding"].get("channel") == "message"
    return Settlement(
        CLEAN, "S1", accepted=True, status=worker.STATUS_COMPLETE,
        inspection_complete=True,
        disposition=NO_FINDING_KNOWN_DETECTOR_GAP if gap else CLEAN)
