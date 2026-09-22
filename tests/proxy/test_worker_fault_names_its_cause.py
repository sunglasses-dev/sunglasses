"""Three failure modes reached the client as one word.

A worker that DIED, a worker that printed something unusable, and a worker whose
output did not fit the contract all settled `SCAN_EXCEPTION` with a result dict
that was byte-identical. They are operationally different: the first says look
at the host, the second says look at the worker, the third says the worker and
this proxy disagree.

The client contract is unchanged -- `status` is still `exception` and the
envelope reason is still `SCAN_EXCEPTION`. The cause is evidence for an
operator, and it rides `detector_status`, a field that was permitted and had
NEVER been used: before this change it appeared exactly once in the whole
repository, in the allowlist itself.
"""
import json
import pathlib

import pytest

from sunglasses.proxy import receipts, route, worker_process

BINDING = {"digest": "d" * 64, "channel": "file", "generation": 1,
           "invocation_token": "0123456789abcdef"}


def _causes_of(*faults):
    return [f.get("detector_status") for f in faults]


def test_a_crash_and_unusable_output_no_longer_look_identical():
    """THE ROW THIS CHANGE EXISTS FOR."""
    crashed = worker_process._fault(BINDING, worker_process.STATUS_EXCEPTION,
                                    worker_process.CAUSE_CRASHED)
    malformed = worker_process._fault(BINDING,
                                      worker_process.STATUS_EXCEPTION,
                                      worker_process.CAUSE_MALFORMED_OUTPUT)
    assert crashed != malformed, (
        "the two faults are still identical, which is the defect")
    assert crashed["status"] == malformed["status"] == "exception", (
        "the premise of this row is that STATUS is deliberately the SAME; the "
        "client contract does not change")
    assert _causes_of(crashed, malformed) == ["crashed", "malformed_output"]


def test_every_cause_is_a_DIFFERENT_value():
    """A control that only checked "a cause is present" would pass if every
    path wrote `crashed` -- which is the shape of the bug being fixed."""
    causes = {worker_process.CAUSE_CRASHED,
              worker_process.CAUSE_MALFORMED_OUTPUT,
              route.CAUSE_SCHEMA_INVALID}
    assert len(causes) == 3, causes


def test_a_deadline_carries_NO_cause():
    """"Still running when time ran out" is already the whole fact. A cause
    invented to avoid a null would describe something that did not happen."""
    timed_out = worker_process._fault(BINDING, worker_process.STATUS_DEADLINE)
    assert "detector_status" not in timed_out, timed_out
    assert timed_out["status"] == "deadline"


def test_unparseable_output_is_labelled_malformed():
    """Driven through the real `_parse`, not by calling `_fault` myself."""
    for raw in (b"", b"not json\n", b'{"a":1}\n{"b":2}\n', b'"a string"\n'):
        fault = worker_process._parse(raw, BINDING)
        assert fault.get("detector_status") == "malformed_output", (raw, fault)
        assert fault["status"] == "exception", (raw, fault)


@pytest.mark.parametrize("good", ["crashed", "malformed_output",
                                  "schema_invalid", None])
def test_the_vocabulary_is_accepted(good):
    """The other direction, or the refusal row below passes by refusing all."""
    assert receipts._check_value("detector_status", good) is None


@pytest.mark.parametrize("bad", ["timeout", "deadline", "", "CRASHED", 1, True])
def test_a_value_outside_the_vocabulary_RAISES(bad):
    with pytest.raises(ValueError):
        receipts._check_value("detector_status", bad)


def test_each_cause_SURVIVES_TO_DISK_as_its_own_value(tmp_path):
    """The read-back, and it asserts the values stay DISTINCT on the file.

    A field permitted in memory can still be dropped by `_clean` on the way to
    disk -- measured here once already with `cause_kind`. And a read-back that
    only checked presence could not see every row collapsing to one value.
    """
    log = receipts.Log(tmp_path, run_id="t-cause", header={})
    for cause in ("crashed", "malformed_output", "schema_invalid"):
        log.event("SCAN_RESULT", accepted=False, status="exception",
                  inspection_complete=False, detector_status=cause)
    rows = []
    for path in sorted((tmp_path / "receipts").glob("*.jsonl")):
        rows += [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    got = [r.get("detector_status") for r in rows if r.get("kind") == "SCAN_RESULT"]
    assert got == ["crashed", "malformed_output", "schema_invalid"], got
    kept = [r.get("status") for r in rows if r.get("kind") == "SCAN_RESULT"]
    assert kept == ["exception"] * 3, (
        "status must still be there beside the new field; a record gaining one "
        "is a record that can lose another")
