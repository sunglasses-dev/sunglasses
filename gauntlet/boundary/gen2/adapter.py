"""Driving a second generation variant, and saying first what it cannot drive.

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
IMPLEMENTED = frozenset({"send_file", "await_primary_terminal"})


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
    missing = {step["op"] for step in steps} - IMPLEMENTED
    if missing:
        raise UnimplementedOperation(missing)
    return steps
