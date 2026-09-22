"""Driving a second generation variant, and saying first what it cannot drive.

BOUND TO ASTRA'S FROZEN STEP CONTRACT. `PROFILE_STEPS.md` in the tools_v2
delivery is the confirmed field contract for the `profile_steps` array in the 74
reference schedules: 40 step types, each with the fields it must carry. Its
digest is pinned below so a schema change breaks visibly instead of drifting,
and `STEP_CONTRACT` is transcribed from that table rather than inferred from the
schedules, because a contract read off its own instances only ever describes
what happened to be delivered.

The document's closing rule is the one that governs everything here:
"Unsupported operations, missing required fields/barriers or skipped required
actions are INVALID ... they must not silently become successful no-ops."

The delivered schedules use 39 distinct `profile_steps` operations and 10
`required_steps` operations across the 74 variants. An adapter that quietly
skipped the ones it has not implemented would produce a full grid of rows that
look like verdicts about a candidate and are really verdicts about itself. Each
delivered schedule says so in its own words: `unknown_operation: INVALID`.

So the set is enumerated here, coverage is planned before anything executes, and
a variant needing an operation this adapter lacks is refused by name. Half a
schedule is worse than none of it, because half a schedule produces evidence.
"""
from __future__ import annotations

# Every operation this adapter can actually execute. Growing it is a deliberate
# edit, made in the same commit as the implementation and the test.
IMPLEMENTED = frozenset({
    "send_file", "await_primary_terminal",
    # The four assertion steps. Measured, not chosen: implementing exactly these
    # takes the drivable set from 19 to 27, and every one of them reads evidence
    # the executor already collects rather than needing new machinery.
    "assert_no_rpc_response_to_notification_or_borrowed_id",
    "assert_zero_upstream_copies",
    "await_client_error",
    "await_error",
    # `await_event` reads the mediator's own receipt stream. It is listed here
    # as an opcode, but the opcode is NOT the unit of capability for it: see
    # SUPPORTED_EVENTS. On its own it unlocks nothing, which is measured rather
    # than assumed — all 24 variants naming it need at least one other
    # unimplemented operation beside it.
    "await_event",
    # Reads the mediator's own WORKER_OUTPUT receipts (`accepted`,
    # `discarded_reason`) — evidence the executor already collects, no new
    # machinery. Added 2026-09-22 with its implementation and its test, as the
    # rule above requires. It is the ONLY one of the four unclassified ops that
    # can be driven today: the other three appear only in variants whose
    # `arm_fault` declares a kind `fault_dispatch.SELECTABLE` cannot select.
    "release_any_old_workers",
    # Added 2026-09-22 with their implementations. `arm_fault` chooses the
    # scanner's mode for the session, which is honest only because every
    # delivered schedule that arms a fault arms BEFORE its first send.
    "arm_fault",
    # Both answered by T8 against the real route and recorded in the capability
    # map with cites re-verified at this head. The second carries a caveat its
    # implementation must honour: independence holds for DISTINCT ids only,
    # because a client id reused while pending is a deliberate teardown.
    "assert_no_second_forward_and_no_pending_overwrite",
    "assert_secondary_and_reverse_complete_independently",
})

# THE EVENTS THIS MEDIATOR ACTUALLY EMITS, of the seven the contract names.
#
# PROFILE_STEPS.md lists REQUEST_RECEIVED, SCAN_STARTED, HOLD_ENTERED,
# CANCEL_ACCEPTED, APPROVAL_INVALIDATED, DESCRIPTOR_CHANGED and UPSTREAM_CLOSED.
# `proxy/passthrough.py` emits twenty event kinds and exactly three of those
# seven are among them. The missing four have plausible-looking neighbours:
# RPC_INGRESS arrives when a request does, PUMP_CLOSED happens when a stream
# ends. Binding REQUEST_RECEIVED to RPC_INGRESS, or UPSTREAM_CLOSED to
# PUMP_CLOSED, would be THIS ADAPTER deciding what the contract's word means,
# and a row built on that substitution reads as a verdict about the candidate
# while really being a verdict about the guess. Recognising the name is not
# recognising the call.
#
# So the four are refused BY NAME until the mediator emits them, and the
# refusal happens in `plan()` rather than at execution time. An opcode-level
# capability check would pass a REQUEST_RECEIVED variant as drivable and then
# fail partway, which is the "half a schedule produces evidence" failure this
# module exists to prevent.
SUPPORTED_EVENTS = frozenset({"SCAN_STARTED", "HOLD_ENTERED", "CANCEL_ACCEPTED",
                              # Mirrored 2026-09-22 after T8 measured the
                              # product on 1e4e526: UPSTREAM_CLOSED is in
                              # `sunglasses.proxy.receipts.EVENTS` and the
                              # harness now emits it with the same discipline,
                              # only after supervising the child.
                              "UPSTREAM_CLOSED"})

# WHY EACH REMAINING EVENT IS REFUSED, in the product's own terms.
#
# "this mediator does not emit X" was true and useless: it invited the reading
# that the harness is behind and should catch up. Three of these are refused
# because THE PRODUCT DOES NOT RECORD THEM EITHER, and mirroring one would mean
# the harness could observe something the shipped route cannot. That is not a
# gap to close; it is the answer.
#
# Measured by T8 on main 1e4e526 and re-checked here by importing
# `sunglasses.proxy.receipts.EVENTS` rather than by reading the report.
EVENT_REFUSAL_REASONS = {
    "REQUEST_RECEIVED": (
        "the product records no such event: ADMITTED and FRAME_IN in "
        "sunglasses/proxy/ carry an id TYPE, never an origin, so 'the upstream "
        "received it' is not a distinction the shipped route can make"),
    "DESCRIPTOR_CHANGED": (
        "the product has this name only as an envelope reason_code in "
        "sunglasses/proxy/approvals.py, retired through `_retire()`. It is a "
        "reason attached to a refusal, not a record of a moment, so awaiting it "
        "would be awaiting the wrong surface"),
    "APPROVAL_INVALIDATED": (
        "the product changes this state in sunglasses/proxy/pump.py and emits "
        "NOTHING for it. There is no record to mirror"),
}

# Every await_event step naming a supported event carries actor `proxy` or
# omits it, and the contract says an omitted actor means proxy. Measured across
# the 74 delivered schedules: 0 exceptions. `upstream` appears only on
# REQUEST_RECEIVED, which is refused above. An upstream-actor event could not be
# answered from the proxy's receipts anyway, so it is refused rather than
# answered from the wrong record.
SUPPORTED_EVENT_ACTORS = frozenset({"proxy"})

# tools_v2/PROFILE_STEPS.md, 2026-09-13. Pinned, not fetched: a contract that
# silently follows the file it describes cannot tell you the file changed.
PROFILE_STEPS_SHA256 = "eadff6b0a5d25f861b34fd1c534eac39fde565a178f734ce308e7beae46438db"

# op -> (required fields, optional fields). Transcribed from the table, in its
# order. `?` in the document means optional; everything else is required, and
# the document says outright that no additional fields are part of this version.
STEP_CONTRACT = {
    "send_file": (("path", "origin"), ()),
    "await_primary_terminal": (("id_from", "timeout_ms"), ()),
    "await_event": (("event", "correlate_id_from", "timeout_ms"), ("actor",)),
    "await_error": (("recipient", "id_from"), ()),
    "await_client_error": (("id_from",), ()),
    "arm_fault": (("kind", "target", "require_fresh_barrier"), ()),
    "execute_armed_worker_fault":
        (("profile", "bind_expected_input_digest_channel_invocation"), ()),
    "release_fault_barrier": ((), ("require_discard", "require_zero_original_forward")),
    "release_any_old_workers": (("require_discard",), ()),
    "assert_pending_retired": (("id_from",), ()),
    "assert_zero_upstream_copies": (("path",), ()),
    "assert_no_rpc_response_to_notification_or_borrowed_id": ((), ()),
    "answer_relist": (("path", "bind_id_from"), ()),
    "answer_next_page": (("path", "bind_id_from"), ()),
    "set_pin_state": (("kind", "baseline", "invalid_file"), ()),
    "assert_no_implicit_approval_or_pin_write": ((), ()),
    "begin_explicit_approval": (("snapshot",), ()),
    "switch_upstream_snapshot": (("snapshot",), ()),
    "commit_reviewed_snapshot_only": ((), ()),
    "assert_pin_matches_reviewed_hash_only": ((), ()),
    "assert_generation_not_activated": ((), ()),
    "launch_and_approve": (("config", "snapshot"), ()),
    "restart_with_same_pin_store": (("config",), ()),
    "assert_no_inherited_approval": ((), ()),
    "assert_secondary_and_reverse_complete_independently": ((), ()),
    "assert_no_second_forward_and_no_pending_overwrite": ((), ()),
    "arm_process_transport_profile": (("name", "limits"), ()),
    "execute_process_transport_profile":
        (("name", "upstream_path", "auxiliary_files", "barrier_and_limit_source"), ()),
    "assert_deadline_and_process_group_cleanup": (("limits",), ()),
    "arm_receipt_profile": (("name",), ()),
    "execute_receipt_profile": (("name", "payload_path", "separate_verifier_inputs"), ()),
    "assert_production_receipt_schema_redaction_and_completion": ((), ()),
    "configure_private_doctor_profile": (("name", "config"), ()),
    "invoke_real_doctor": (("capture_output", "capture_children_and_receipts"), ()),
    "assert_configured_route_status": (("allow_separate_selftest_result", "profile"), ()),
    "snapshot_private_config_bytes_and_mode": (("config",), ()),
    "invoke_real_install": (("entry", "config"), ()),
    "execute_config_transaction_profile": (("name", "config"), ()),
    "invoke_real_uninstall_if_profile_allows": (("entry",), ()),
    "compare_config_bytes_entries_mode_and_claim": (("profile",), ()),
}


class StepContractViolation(Exception):
    """A step is not the shape the frozen contract says it is."""


def check_step(step: dict) -> None:
    """Raise unless `step` matches its row in PROFILE_STEPS.md exactly.

    Checked BEFORE anything executes. A step missing a required field can always
    be executed approximately, and an approximate run still produces a row that
    reads like a verdict about the candidate.
    """
    op = step.get("op")
    if op not in STEP_CONTRACT:
        raise StepContractViolation(
            f"{op!r} is not one of the 40 step types in the frozen contract. "
            "An unrecognised opcode is INVALID, never a no-op.")
    required, optional = STEP_CONTRACT[op]
    present = set(step) - {"op"}
    missing = sorted(set(required) - present)
    if missing:
        raise StepContractViolation(
            f"{op}: required field(s) {missing} are absent. The contract lists "
            f"{sorted(required)} and the step carries {sorted(present)}.")
    extra = sorted(present - set(required) - set(optional))
    if extra:
        raise StepContractViolation(
            f"{op}: unexpected field(s) {extra}. The document says no additional "
            "fields or silent opcode substitutions are part of this version, so "
            "an extra field means this schedule is not the one described.")


class UnsupportedEvent(Exception):
    """An await_event step names an event this mediator does not emit."""

    def __init__(self, requests):
        self.requests = sorted(set(requests))
        detail = ", ".join(f"{event} (actor {actor})" for event, actor in self.requests)
        # NAMED, one line each, in the product's terms. A refusal that only says
        # "not supported" reads as a to-do; these are refused because the
        # PRODUCT does not record them, and mirroring one would let the harness
        # observe something the shipped route cannot.
        why = "; ".join(
            f"{event}: {EVENT_REFUSAL_REASONS[event]}"
            for event, _ in self.requests if event in EVENT_REFUSAL_REASONS)
        super().__init__(
            "this mediator does not emit " + detail + ". "
            + (why + ". " if why else "")
            + "Answering one of these from a neighbouring event that arrives at "
            "a similar moment would make this adapter the author of the "
            "scenario's meaning, so the variant is refused whole.")


class NoStepsToDrive(Exception):
    """A schedule with no steps in it. Not an empty run, a missing one."""


class UnimplementedOperation(Exception):
    """A schedule asks for operations this adapter does not implement."""

    def __init__(self, operations):
        self.operations = sorted(set(operations))
        super().__init__(
            "this adapter cannot drive " + ", ".join(self.operations)
            + ". A partially executed schedule produces evidence about a "
            "scenario that did not happen, so the variant is refused whole.")


def plan(schedule: dict) -> list[dict]:
    """The steps that would run, or a refusal naming the ones that could not.

    Checked across the WHOLE schedule before returning any of it. Returning the
    prefix that happens to be drivable is the failure this guards against.
    """
    steps = list(schedule.get("profile_steps") or [])
    if not steps:
        # ZERO STEPS IS A REFUSAL, not a plan that happens to be short. A caller
        # that handed over the wrong document got an empty list back and drove a
        # session with no request in it, and the run then reported an upstream
        # that never answered, which reads as a defect in the thing under test.
        raise NoStepsToDrive(
            f"{schedule.get('scenario_id')}.{schedule.get('variant')}: this "
            "schedule declares no profile_steps. A schedule with no steps is a "
            "document this adapter was handed by mistake, not a variant that "
            "needs nothing done.")
    # SHAPE FIRST, then capability. A step that does not match the frozen
    # contract is not a step at all, and asking whether this adapter implements
    # an operation whose fields are wrong answers the less important question.
    for step in steps:
        check_step(step)
    missing = {step["op"] for step in steps} - IMPLEMENTED
    if missing:
        raise UnimplementedOperation(missing)
    # CAPABILITY FINER THAN THE OPCODE. `await_event` is implemented, but only
    # for the events the mediator actually emits, so the whole schedule is
    # checked for the ones it does not before any of it is returned. Same rule
    # as above and for the same reason: refused whole, never driven in part.
    unsupported = {
        (step["event"], step.get("actor", "proxy"))
        for step in steps
        if step["op"] == "await_event"
        and (step["event"] not in SUPPORTED_EVENTS
             or step.get("actor", "proxy") not in SUPPORTED_EVENT_ACTORS)
    }
    if unsupported:
        raise UnsupportedEvent(unsupported)
    return steps


# THE OUTCOMES `plan` HAS FOR A VARIANT, named because two of them were being
# counted as one population. A variant is refused for an operation this adapter
# does not implement OR for an event this mediator does not emit, and every
# consumer that knew only the first still summed to 74: the operation check runs
# first, and until `release_any_old_workers` was implemented every variant with
# an event gap also had a missing operation, so the second refusal was never
# reached. Four variants then fell out of the accounting entirely. A refusal
# class nobody names is a refusal class nobody counts.
DRIVABLE = "drivable"
MISSING_OPERATION = "missing_operation"
EVENT_GAP = "event_gap"
NO_STEPS = "no_steps"

CLASSES = (DRIVABLE, MISSING_OPERATION, EVENT_GAP, NO_STEPS)


def classify(schedule: dict) -> str:
    """Which of `CLASSES` this schedule falls into, by the same call that drives.

    Defined HERE and not in each consumer, so that a new refusal class shows up
    everywhere the moment `plan` can raise it, rather than in whichever counter
    someone remembered to update.
    """
    try:
        plan(schedule)
    except UnimplementedOperation:
        return MISSING_OPERATION
    except UnsupportedEvent:
        return EVENT_GAP
    except NoStepsToDrive:
        return NO_STEPS
    return DRIVABLE
