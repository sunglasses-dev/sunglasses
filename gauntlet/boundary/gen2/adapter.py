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
})

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
    return steps
