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
    schedule = {"profile_steps": [
        {"op": "send_file", "origin": "client", "path": "a.jsonl"},
        {"op": "arm_fault", "target": "worker"},
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
    assert adapter.IMPLEMENTED == frozenset({"send_file", "await_primary_terminal"})


def test_coverage_over_the_real_delivery_is_reported_and_not_rounded():
    """How much of the delivery this adapter can drive today, exactly.

    Written as numbers rather than a ratio so a variant moving from cannot to
    can shows up as a one line change. Today the adapter drives the shape G2-13
    uses and nothing else, which is 19 of 74 variants, and every other variant
    is refused by name rather than half run.

    19 is measured, not chosen. The first version of this test said 18 because I
    guessed, and the count corrected me.
    """
    drivable, refused, missing_ops = [], [], set()
    for entry in runner.load_manifest()["scenarios"]:
        for variant in runner.scenario_of(entry)["variants"]:
            if "routes" not in variant:
                continue
            record = artifacts.of_record(entry, variant)
            try:
                adapter.plan(record.schedule)
                drivable.append(f"{entry['id']}.{variant['name']}")
            except adapter.UnimplementedOperation as exc:
                refused.append(f"{entry['id']}.{variant['name']}")
                missing_ops |= set(exc.operations)

    assert len(drivable) + len(refused) == 74, (len(drivable), len(refused))
    assert len(drivable) == 19, sorted(drivable)
    assert "arm_fault" in missing_ops, sorted(missing_ops)
    assert not (missing_ops & adapter.IMPLEMENTED), (
        "an operation cannot be both implemented and missing")
