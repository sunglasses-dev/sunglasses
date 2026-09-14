"""The four assertion steps, recorded as observations rather than raised.

These are the measured next unlock: 19 drivable variants becomes 27, over
evidence the executor already collects. None of them needs new machinery.

THE IMPORTANT DECISION IS THAT THEY DO NOT RAISE. `assert_zero_upstream_copies`
is expected to FAIL on the control route, because the control is defined by
having nothing in the middle, so the copy does reach the upstream and that is
the finding. A step that threw would turn the control's whole purpose into an
error, and the grader would never see the row.

An exception here means the harness could not carry out the step. A recorded
`held: false` means it carried it out and the answer was no.
"""
import json
import pathlib
import shutil
import sys
import uuid

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import runner                                                   # noqa: E402
from gen2 import adapter, artifacts, execute                    # noqa: E402


def _case(scenario_id, variant_name):
    entry = next(e for e in runner.load_manifest()["scenarios"]
                 if e["id"] == scenario_id)
    variant = next(v for v in runner.scenario_of(entry)["variants"]
                   if v["name"] == variant_name)
    return entry, variant


@pytest.fixture
def run_root():
    root = pathlib.Path("/private/tmp") / f"gen2-assert-{uuid.uuid4().hex[:10]}"
    yield root
    shutil.rmtree(root, ignore_errors=True)


def _held(run, op):
    return next(a for a in run.assertions if a["op"] == op)


def test_the_four_assertion_ops_are_implemented():
    """Enumerated in the adapter, so a variant needing one is no longer refused."""
    for op in ("assert_no_rpc_response_to_notification_or_borrowed_id",
               "assert_zero_upstream_copies", "await_client_error", "await_error"):
        assert op in adapter.IMPLEMENTED, op


def test_a_notification_gets_no_response_and_no_id_is_borrowed(run_root):
    """G2-14.upstream_log: the upstream sends a notification carrying the payload.

    Nothing may answer it, and nothing may answer the pending request 1401 with
    it either. Both halves are the same rule about correlation.
    """
    entry, variant = _case("G2-14", "upstream_log")
    run = execute.run(entry, variant, route="no_mediation", run_root=run_root,
                      timeout_ms=8000)
    check = _held(run, "assert_no_rpc_response_to_notification_or_borrowed_id")
    assert check["held"] is True, check


def test_a_borrowed_id_is_caught():
    """The rule itself, on the shape G2-15 produces.

    This was written against G2-15.reverse_request's RUN, and that variant does
    not declare the correlation step at all, so the run recorded no such
    assertion and the test asked for something that was never there. The rule is
    what needed proving, and it is proved here directly: a client request 1501
    still pending, and an upstream frame carrying 1501 while being a request of
    its own.
    """
    client = [{"jsonrpc": "2.0", "id": 1501, "method": "tools/call", "params": {}}]
    upstream = [{"jsonrpc": "2.0", "id": 1501, "method": "sampling/createMessage",
                 "params": {}}]
    check = execute._check_correlation(client, upstream)
    assert check["held"] is False
    assert check["borrowed_ids"] == [1501]


def test_an_ordinary_reply_is_not_a_borrowed_id():
    """The control for it. A reply to a pending request is the normal case."""
    client = [{"jsonrpc": "2.0", "id": 1501, "method": "tools/call", "params": {}}]
    upstream = [{"jsonrpc": "2.0", "id": 1501, "result": {"ok": True}}]
    assert execute._check_correlation(client, upstream)["held"] is True


def test_a_reply_nobody_asked_for_is_caught():
    """G2-20's shape: an answer carrying an id the client never sent."""
    client = [{"jsonrpc": "2.0", "id": 2003, "method": "tools/call", "params": {}}]
    upstream = [{"jsonrpc": "2.0", "id": 82003, "result": {"ok": True}}]
    check = execute._check_correlation(client, upstream)
    assert check["held"] is False
    assert check["unrequested_reply_ids"] == [82003]


def test_the_control_route_does_deliver_the_copy_and_says_so(run_root):
    """`assert_zero_upstream_copies` on the control, where it is expected to fail.

    G2-14.client_notification sends a client notification whose `_meta` carries a
    secret. On the control there is nothing in the middle, so the copy reaches
    the upstream. The step records that it did; it does not raise, because the
    control's finding IS that the copy arrives.
    """
    entry, variant = _case("G2-14", "client_notification")
    run = execute.run(entry, variant, route="no_mediation", run_root=run_root,
                      timeout_ms=8000)
    check = _held(run, "assert_zero_upstream_copies")
    assert check["held"] is False, check
    assert check["copies"] >= 1, check


def test_an_await_records_the_deadline_that_applied(run_root):
    """The contract: these two carry no per-step timeout, so the run has to say
    which deadline was used. A wait with an unrecorded bound is not a
    measurement anybody else can repeat."""
    entry, variant = _case("G2-15", "reverse_request")
    run = execute.run(entry, variant, route="no_mediation", run_root=run_root,
                      timeout_ms=8000)
    check = _held(run, "await_error")
    assert check["deadline_ms"] == 8000, check
    assert check["recipient"] == "upstream", check


def test_the_assertions_are_in_the_execution_record(run_root):
    entry, variant = _case("G2-14", "upstream_log")
    run = execute.run(entry, variant, route="no_mediation", run_root=run_root,
                      timeout_ms=8000)
    record = json.loads((run.run_dir / "execution.json").read_text())
    assert [a["op"] for a in record["assertions"]] == [a["op"] for a in run.assertions]
