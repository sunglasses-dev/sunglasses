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


# ── TYPED IDS: "2001" and 2001 are two ids, and every record must keep them two ──
#
# G2-20.typed_ids exists to put a string id and a number id with the same digits
# on the wire at once. On c09f7ff it was counted DRIVABLE at plan level and had
# never completed a run: the independence step called `sorted()` over a mix of
# str and int and raised TypeError, and a Counter rendered with `dict(...)`
# would have merged the two ids into one JSON key had it got that far.
# The scenario's own subject is what broke the instrument that measures it.

def test_mixed_type_ids_are_two_ids_in_the_independence_record():
    settled = [{"request_id": 2001}, {"request_id": "2001"}]
    check = json.loads(json.dumps(execute._independence(settled)))
    assert sorted(map(json.dumps, check["distinct_ids"])) == ['"2001"', "2001"]
    assert check["reused_ids"] == []
    assert len(check["settled_per_id"]) == 2, check["settled_per_id"]
    assert check["held"] is True


def test_a_reused_id_is_still_caught_when_its_twin_has_another_type():
    """The control: typing the key must not make a real reuse disappear."""
    settled = [{"request_id": 2001}, {"request_id": 2001}, {"request_id": "2001"}]
    check = json.loads(json.dumps(execute._independence(settled)))
    assert check["reused_ids"] == [2001]
    assert check["distinct_ids"] == ["2001"]
    assert check["held"] is False


def test_no_settlement_is_no_subject_not_a_pass():
    check = execute._independence([])
    assert check["subject"] is False and check["held"] is None


def test_mixed_type_ids_do_not_break_the_correlation_check():
    client = [{"jsonrpc": "2.0", "id": "2001", "method": "tools/call", "params": {}},
              {"jsonrpc": "2.0", "id": 2001, "method": "tools/call", "params": {}}]
    upstream = [{"jsonrpc": "2.0", "id": 2001, "method": "ping", "params": {}},
                {"jsonrpc": "2.0", "id": 9, "result": {}},
                {"jsonrpc": "2.0", "id": "9", "result": {}}]
    check = execute._check_correlation(client, upstream)
    assert check["borrowed_ids"] == [2001]
    assert sorted(map(json.dumps, check["unrequested_reply_ids"])) == ['"9"', "9"]
    assert check["held"] is False


def test_per_id_counts_survive_json_with_both_types():
    counts = json.loads(json.dumps(execute._per_id([2001, "2001", "2001"])))
    assert counts == {"int:2001": 1, 'str:"2001"': 2}, counts


# ── A FAULT THAT HELD MORE THAN IT NAMES ────────────────────────────────────
#
# Measured on G2-20.typed_ids after the typed-id fix let it finish: the scanner
# command is fixed per session, so `barrier` holds EVERY scan, not the one item
# the arm_fault kind names. The secondary was held by the primary's fault,
# killed at SCAN_DEADLINE, settled once, and the independence row read
# held:true. "Completed independently" was "refused because the fault leaked
# onto it". Not a pass and not a fail: the experiment did not happen.

def test_a_barrier_that_held_two_items_voids_independence():
    settled = [{"request_id": 2001, "reason": "SCAN_DEADLINE"}]
    check = execute._independence(settled, barrier_held_ids=[2001, "2001"])
    assert check["subject"] is False and check["held"] is None, check
    assert "barrier" in check["why"]
    assert sorted(map(json.dumps, check["fault_scope"]["held_by_barrier"])) == \
        ['"2001"', "2001"]


def test_a_barrier_that_held_one_item_leaves_independence_measurable():
    """The control: the guard must not void the case it exists to allow."""
    settled = [{"request_id": 2001, "reason": "CLEAN"}]
    check = execute._independence(settled, barrier_held_ids=["2001"])
    assert check["subject"] is True and check["held"] is True, check


# ── THE BARRIER, SCOPED TO THE ITEM THE FAULT NAMES ─────────────────────────
from gen2 import scoped_barrier                                  # noqa: E402


def test_the_named_item_is_held():
    target = {"id": "2001", "direction": "result"}
    assert scoped_barrier.is_target({"id": "2001", "direction": "result"}, target)


def test_a_same_digits_id_of_another_type_is_not_held():
    target = {"id": "2001", "direction": "result"}
    assert not scoped_barrier.is_target({"id": 2001, "direction": "result"}, target)


def test_the_same_id_in_the_other_direction_is_not_held():
    target = {"id": "2001", "direction": "result"}
    assert not scoped_barrier.is_target({"id": "2001", "direction": "request"}, target)


def test_an_item_the_mediator_did_not_name_is_not_held():
    """Fail toward scanning: holding unnamed items IS the session-wide bug."""
    target = {"id": "2001", "direction": "result"}
    assert not scoped_barrier.is_target(None, target)
    assert not scoped_barrier.is_target({"direction": "result"}, target)


# ── THE RELEASE HAPPENS IN THE SESSION, AFTER THE HOLD BEGAN ────────────────
#
# It used to run after the server exited: every held item died at
# SCAN_DEADLINE and the row said released:true.

def test_a_release_waits_for_the_hold_and_then_releases(tmp_path):
    (tmp_path / "barrier.held.jsonl").write_text('{"id": "2001", "direction": "result"}\n')
    rec = execute._release_in_session(tmp_path, {"id": "2001", "direction": "result"}, 500)
    assert rec["in_session"] is True and rec["hold_entered"] is True
    assert (tmp_path / "fault.release").is_file()


def test_a_hold_that_never_began_is_not_released(tmp_path):
    """The control: no fresh barrier, so no release file, and it says why."""
    rec = execute._release_in_session(tmp_path, {"id": "2001", "direction": "result"}, 50)
    assert rec["in_session"] is False and rec["hold_entered"] is False
    assert not (tmp_path / "fault.release").exists()
    assert "never entered the hold" in rec["why"]


def test_an_unscoped_barrier_is_not_released_in_session(tmp_path):
    rec = execute._release_in_session(tmp_path, None, 50)
    assert rec["in_session"] is False
    assert not (tmp_path / "fault.release").exists()


@pytest.mark.parametrize("mode", ["head_of_line", "contract"])
def test_typed_ids_has_a_subject_in_both_mediator_modes(run_root, mode):
    """End to end: the secondary completes, the primary is held, released in
    session, and delivered. Before: the secondary died under the primary's
    barrier and the primary died at the deadline, in both modes."""
    entry, variant = _case("G2-20", "typed_ids")
    run = execute.run(entry, variant, route="proxy_strict", run_root=run_root,
                      mode=mode, engine_root=pathlib.Path(__file__).resolve().parents[3])
    arm = _held(run, "arm_fault")
    assert arm["fault_scope"] == {"id": "2001", "direction": "result"}
    assert arm["mediator_mode"] == mode
    independence = _held(run, "assert_secondary_and_reverse_complete_independently")
    assert independence["subject"] is True and independence["held"] is True, independence
    release = _held(run, "release_fault_barrier")
    assert release["held"] is True and release["release"]["hold_entered"] is True, release
    settled = execute._receipts_of_kind(run_root / "proxy.receipts.jsonl", "SETTLED")
    assert sorted((json.dumps(r["request_id"]), r["reason"], r["forwarded"]) for r in settled) \
        == [('"2001"', "CLEAN", True), ("2001", "CLEAN", True)], settled
