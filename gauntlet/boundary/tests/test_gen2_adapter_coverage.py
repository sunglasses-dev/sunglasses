"""What the adapter can drive, said out loud, before it drives anything.

The delivered schedules use 39 distinct `profile_steps` operations and 10
`required_steps` operations across the 74 second generation variants. An adapter
that quietly skips the ones it has not implemented produces a full grid of rows
that look like verdicts about a candidate and are really verdicts about itself.
That is the reading error the Gate 2 exam threw out 20 rows over, and each
delivered schedule says it in its own words: `unknown_operation: INVALID`.

So coverage is enumerated and pinned. Adding an operation is a deliberate edit
to a written list, and a seed that needs one the adapter lacks is refused by
name rather than partially run.
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import runner                                              # noqa: E402
from gen2 import adapter, artifacts                        # noqa: E402


def test_a_schedule_of_implemented_operations_plans():
    schedule = {"profile_steps": [
        {"op": "send_file", "origin": "client", "path": "a.jsonl"},
        {"op": "await_primary_terminal", "id_from": "a.jsonl", "timeout_ms": 3000},
    ]}

    assert [step["op"] for step in adapter.plan(schedule)] == \
        ["send_file", "await_primary_terminal"]


def test_an_operation_the_adapter_cannot_drive_is_refused_by_name():
    """Named, and refused before anything runs.

    A partially executed schedule is worse than a refused one: it produces
    evidence, and the evidence is about a scenario that did not happen.
    """
    # A CONTRACT-VALID step, deliberately. `plan` checks shape before capability,
    # so a hand-made step missing its required fields would be refused for the
    # wrong reason and this test would pass while proving something else.
    schedule = {"profile_steps": [
        {"op": "send_file", "origin": "client", "path": "a.jsonl"},
        {"op": "arm_fault", "kind": "barrier_hold", "target": "scanner_worker",
         "require_fresh_barrier": True},
    ]}

    with pytest.raises(adapter.UnimplementedOperation) as exc:
        adapter.plan(schedule)

    assert "arm_fault" in str(exc.value), str(exc.value)
    assert "send_file" not in str(exc.value), (
        "the refusal should name what is missing, not what is fine")


def test_the_operations_this_adapter_implements_are_written_down():
    """The list is the contract. Growth is a diff, never a surprise.

    If this assertion fails because the adapter grew, that is correct and the
    fix is to update the list in the same commit that adds the operation.
    """
    assert adapter.IMPLEMENTED == frozenset({
        "send_file", "await_primary_terminal",
        "assert_no_rpc_response_to_notification_or_borrowed_id",
        "assert_zero_upstream_copies", "await_client_error", "await_error",
        # Added with its implementation and tests. The opcode is NOT the unit
        # of capability for it: `SUPPORTED_EVENTS` is pinned separately below,
        # because this mediator emits three of the contract's seven events.
        "await_event",
        # Answered from the mediator's own WORKER_OUTPUT receipts, which carry
        # `accepted` and `discarded_reason`. Implementing it did NOT make any
        # variant drivable: all five that name it also await events this
        # mediator does not emit, and the op refusal had been masking that.
        "release_any_old_workers"})


def test_the_events_this_adapter_can_answer_are_written_down():
    """Pinned beside IMPLEMENTED, because the opcode alone would overstate it.

    `await_event` is implemented, but a schedule naming an event this mediator
    never emits is refused at plan time. Growing this set means the mediator
    started emitting something, which is a deliberate change to
    `proxy/passthrough.py` and belongs in that commit, not this one.
    """
    assert adapter.SUPPORTED_EVENTS == frozenset({
        "SCAN_STARTED", "HOLD_ENTERED", "CANCEL_ACCEPTED",
        # Added 2026-09-22 with the harness emission that backs it. The bar is
        # not "the scenario asks for it" — it is that the PRODUCT records it:
        # `sunglasses.proxy.receipts.EVENTS` carries UPSTREAM_CLOSED, and the
        # harness now emits it after supervising the child, as session.py does.
        "UPSTREAM_CLOSED"})

    # AND THE THREE THAT STAY OUT, each with the product's reason. A refusal
    # that only says "unsupported" reads as a to-do; these are refused because
    # the product does not record them either, so mirroring one would let the
    # harness observe what the shipped route cannot.
    assert set(adapter.EVENT_REFUSAL_REASONS) == {
        "REQUEST_RECEIVED", "DESCRIPTOR_CHANGED", "APPROVAL_INVALIDATED"}
    assert not (set(adapter.EVENT_REFUSAL_REASONS) & adapter.SUPPORTED_EVENTS), (
        "an event cannot be both answerable and refused")
    assert adapter.SUPPORTED_EVENT_ACTORS == frozenset({"proxy"})


def test_coverage_over_the_real_delivery_is_reported_and_not_rounded():
    """How much of the delivery this adapter can drive today, exactly.

    Written as numbers rather than a ratio so a variant moving from cannot to
    can shows up as a one line change. Today the adapter drives the shape G2-13
    uses and nothing else, which is 27 of 74 variants, and every other variant
    is refused by name rather than half run.

    19 is measured, not chosen. The first version of this test said 18 because I
    guessed, and the count corrected me.
    """
    # THREE BUCKETS, not two. `plan` refuses for a missing operation OR for an
    # event this mediator never emits, and only the first was counted here. The
    # sum reached 74 anyway because the op check runs first and every variant
    # with an event gap also had a missing op, so the second refusal was never
    # reached. Implementing `release_any_old_workers` removed the mask and four
    # variants fell out of the accounting entirely, which is how a coverage
    # number comes to describe a population it no longer covers.
    counted = {name: [] for name in adapter.CLASSES}
    missing_ops = set()
    for entry in runner.load_manifest()["scenarios"]:
        for variant in runner.scenario_of(entry)["variants"]:
            if "routes" not in variant:
                continue
            record = artifacts.of_record(entry, variant)
            counted[adapter.classify(record.schedule)].append(
                f"{entry['id']}.{variant['name']}")
            try:
                adapter.plan(record.schedule)
            except adapter.UnimplementedOperation as exc:
                missing_ops |= set(exc.operations)
            except Exception:
                pass

    drivable = counted[adapter.DRIVABLE]
    refused = counted[adapter.MISSING_OPERATION]
    event_refused = counted[adapter.EVENT_GAP]

    # EVERY class, summed from the classifier itself. Naming the buckets in the
    # test is what let the previous version sum two of three to 74 and call it
    # whole; this cannot miss a class without failing here first.
    assert sum(len(v) for v in counted.values()) == 74, {
        k: len(v) for k, v in counted.items()}
    # 27, measured. It was 19 before the four assertion steps, which were chosen
    # because the sweep said those four unlock the most for the least.
    assert len(drivable) == 27, sorted(drivable)
    # The four G2-21 variants whose remaining blocker is an event, not an op.
    assert len(event_refused) == 4, sorted(event_refused)
    assert len(refused) == 43, len(refused)
    assert "arm_fault" in missing_ops, sorted(missing_ops)
    assert not (missing_ops & adapter.IMPLEMENTED), (
        "an operation cannot be both implemented and missing")
