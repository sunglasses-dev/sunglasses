"""`await_event`, and the four events this mediator cannot answer.

The frozen step contract names seven events. `proxy/passthrough.py` emits three
of them. The other four have neighbours in the receipt stream that arrive at a
similar moment and mean something else, and binding a contract word to a
neighbour would make this adapter the author of the scenario's meaning rather
than its driver. So the opcode is implemented and the four are refused BY NAME,
at plan time, before any of the schedule runs.

The refusal is the interesting part and every test here that asserts one is
paired with the mutation that must break it.
"""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from gen2 import adapter, execute                          # noqa: E402


def _await(event, **extra):
    """A contract-valid await_event step. Shape is checked before capability,
    so a hand-made step missing a required field would be refused for the wrong
    reason and the test would pass while proving something else."""
    step = {"op": "await_event", "event": event,
            "correlate_id_from": "main.requests.jsonl", "timeout_ms": 3000}
    step.update(extra)
    return step


# ── what plan() accepts and refuses ──────────────────────────────────────────

@pytest.mark.parametrize("event", sorted(adapter.SUPPORTED_EVENTS))
def test_an_emitted_event_plans(event):
    assert [s["op"] for s in adapter.plan({"profile_steps": [_await(event)]})] \
        == ["await_event"]


@pytest.mark.parametrize("event", ["REQUEST_RECEIVED", "UPSTREAM_CLOSED",
                                   "APPROVAL_INVALIDATED", "DESCRIPTOR_CHANGED"])
def test_an_event_the_mediator_does_not_emit_is_refused_by_name(event):
    """The four the contract names and passthrough.py does not emit."""
    with pytest.raises(adapter.UnsupportedEvent) as refusal:
        adapter.plan({"profile_steps": [_await(event)]})
    assert event in str(refusal.value)


def test_the_refusal_names_every_unsupported_event_not_just_the_first():
    """A schedule asking for two gets told about two.

    Reporting only the first would send a reader back for another round per
    event, and the whole point of refusing at plan time is to say what is
    missing once.
    """
    with pytest.raises(adapter.UnsupportedEvent) as refusal:
        adapter.plan({"profile_steps": [_await("REQUEST_RECEIVED"),
                                        _await("UPSTREAM_CLOSED")]})
    assert "REQUEST_RECEIVED" in str(refusal.value)
    assert "UPSTREAM_CLOSED" in str(refusal.value)


def test_a_supported_event_for_the_upstream_actor_is_refused():
    """The proxy's receipts are the PROXY's record.

    An upstream-actor event answered out of the mediator's own stream would be
    answered from the wrong record, so it is refused rather than approximated.
    """
    with pytest.raises(adapter.UnsupportedEvent):
        adapter.plan({"profile_steps": [_await("HOLD_ENTERED", actor="upstream")]})


def test_an_omitted_actor_is_the_contract_default_and_plans():
    """PROFILE_STEPS.md: "Omitted actor means proxy"."""
    step = _await("HOLD_ENTERED")
    assert "actor" not in step
    assert adapter.plan({"profile_steps": [step]})


def test_the_whole_schedule_is_refused_not_the_drivable_prefix():
    """Half a schedule produces evidence about a scenario that did not happen."""
    with pytest.raises(adapter.UnsupportedEvent):
        adapter.plan({"profile_steps": [
            {"op": "send_file", "origin": "client", "path": "a.jsonl"},
            _await("UPSTREAM_CLOSED"),
        ]})


def test_shape_is_checked_before_capability():
    """A step with a missing required field is not a step at all.

    Asking whether this adapter supports an event whose step is malformed
    answers the less important question.
    """
    with pytest.raises(adapter.StepContractViolation):
        adapter.plan({"profile_steps": [
            {"op": "await_event", "event": "REQUEST_RECEIVED", "timeout_ms": 3000}]})


# ── correlating an event to a request ────────────────────────────────────────

def _receipts(tmp_path, *events):
    path = tmp_path / "proxy.receipts.jsonl"
    path.write_text("".join(json.dumps(e) + "\n" for e in events))
    return path


def _event(kind, request_id, seq=0):
    return {"run_id": "r", "seq": seq, "kind": kind, "request_id": request_id,
            "request_id_type": type(request_id).__name__}


def test_an_event_for_the_correlated_id_is_found(tmp_path):
    path = _receipts(tmp_path, _event("HOLD_ENTERED", 1312))
    assert execute._event_for(path, "HOLD_ENTERED", 1312)["seq"] == 0


def test_a_different_id_does_not_answer(tmp_path):
    path = _receipts(tmp_path, _event("HOLD_ENTERED", 1312))
    assert execute._event_for(path, "HOLD_ENTERED", 9999) is None


def test_a_different_kind_does_not_answer(tmp_path):
    path = _receipts(tmp_path, _event("SCAN_STARTED", 1312))
    assert execute._event_for(path, "HOLD_ENTERED", 1312) is None


def test_a_string_id_does_not_answer_for_an_integer_one(tmp_path):
    """4 and "4" are different correlation ids in JSON-RPC and render the same.

    DOCUMENTS THE RULE, DOES NOT GUARD IT. Deleting the `request_id_type`
    comparison leaves this test green, because Python already calls "1312"
    unequal to 1312. The test below is the one that holds that line, and it is
    recorded here so a later reader does not mistake this for the guard's cover
    and delete the one that is.
    """
    path = _receipts(tmp_path, _event("HOLD_ENTERED", "1312"))
    assert execute._event_for(path, "HOLD_ENTERED", 1312) is None
    assert execute._event_for(path, "HOLD_ENTERED", "1312") is not None


def test_a_boolean_does_not_answer_for_one(tmp_path):
    """Python calls True equal to 1. JSON-RPC does not.

    THE LOAD-BEARING TYPE TEST: this is the case `!=` alone gets wrong, so
    removing the `request_id_type` comparison fails here and nowhere else.
    """
    path = _receipts(tmp_path, _event("HOLD_ENTERED", True))
    assert execute._event_for(path, "HOLD_ENTERED", 1) is None


def test_the_first_matching_event_wins(tmp_path):
    path = _receipts(tmp_path, _event("HOLD_ENTERED", 7, seq=3),
                     _event("HOLD_ENTERED", 7, seq=9))
    assert execute._event_for(path, "HOLD_ENTERED", 7)["seq"] == 3


def test_no_receipts_file_is_absence_not_an_error(tmp_path):
    """The control route has no mediator, so it has no receipts.

    A control that emits no proxy event is the definition of the control. This
    raising would turn that finding into an error the grader never sees.
    """
    assert execute._event_for(tmp_path / "absent.jsonl", "HOLD_ENTERED", 1) is None


def test_a_truncated_line_is_skipped_not_fatal(tmp_path):
    """Receipts are appended and flushed during the run, so a reader can meet a
    half line if the session died mid write."""
    path = tmp_path / "proxy.receipts.jsonl"
    path.write_text('{"kind": "HOLD_ENT\n' + json.dumps(_event("HOLD_ENTERED", 5)) + "\n")
    assert execute._event_for(path, "HOLD_ENTERED", 5) is not None
