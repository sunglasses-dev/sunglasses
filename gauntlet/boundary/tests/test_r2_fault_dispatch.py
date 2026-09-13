"""The dispatcher has to SELECT the fault, not merely be configured with one.

ASTRA's vendored test reads the configuration and checks the modes are named in
it. That is the right thing for him to check and it is not enough on its own: a
dispatcher that names three modes in its argv and then runs an ordinary scan
every time would pass it, and every G2-08/09/11 row would go on measuring an
unfaulted session exactly as before. A green configuration test over an inert
capability is the shape of defect this whole repair is about.

So these drive the dispatcher.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from proxy import fault_dispatch                              # noqa: E402

HELD = "the document this scenario declares a fault for\n"
OTHER = "a different document in the same session\n"


def _run_dir(tmp_path, kind, payload=HELD):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "result.payload.txt").write_text(payload)
    (run_dir / "materialised.fault.json").write_text(json.dumps({
        "scenario_id": "G2-09", "variant": "result",
        "fault": {"kind": kind, "direction": "result"},
        "payload": "result.payload.txt",
        "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(),
    }))
    return run_dir


@pytest.mark.parametrize("kind,mode", [("exception", "exception"),
                                       ("hang", "hang"),
                                       ("barrier_hold", "barrier")])
def test_the_declared_fault_is_selected_for_the_declared_payload(tmp_path, kind, mode):
    """`barrier_hold` in the scenario, `barrier` on the worker's command line."""
    assert fault_dispatch.declared_fault(_run_dir(tmp_path, kind), HELD) == mode


def test_a_different_document_in_the_same_session_is_not_faulted(tmp_path):
    """The control, and the reason matching is by digest rather than by order.

    G2-11 holds one request under a barrier and requires a second request, id
    112, to complete normally in the same session. A dispatcher that faulted the
    first message it saw would fault whichever one the pump happened to hand it
    first, and the pump deliberately does not preserve order.
    """
    assert fault_dispatch.declared_fault(_run_dir(tmp_path, "hang"), OTHER) is None


def test_a_run_with_no_declared_fault_scans(tmp_path):
    run_dir = tmp_path / "plain"
    run_dir.mkdir()
    assert fault_dispatch.declared_fault(run_dir, HELD) is None


def test_an_unreadable_fault_record_scans_rather_than_guessing(tmp_path):
    """Injecting a fault nobody asked for is worse than missing one that was.

    A row that was faulted by accident still produces a verdict, and the verdict
    looks like a candidate defect.
    """
    run_dir = tmp_path / "broken"
    run_dir.mkdir()
    (run_dir / "materialised.fault.json").write_text("{not json")
    assert fault_dispatch.declared_fault(run_dir, HELD) is None


def test_the_dispatcher_actually_runs_the_faulted_worker(tmp_path):
    """End to end through the real package worker, not just the decision.

    `exception` because it is the one that terminates by itself: a non-zero exit
    from the package's own fault_worker is the observable proof that the mode
    reached it.
    """
    run_dir = _run_dir(tmp_path, "exception")
    completed = subprocess.run(
        [sys.executable, str(pathlib.Path(fault_dispatch.__file__)),
         "--run-dir", str(run_dir), "--channel", "api_response"],
        input=HELD.encode(), capture_output=True)

    assert completed.returncode != 0, "the exception fault did not reach the worker"
    assert b"GATE2 synthetic scanner exception" in completed.stderr, completed.stderr[-400:]
    assert (run_dir / "fault.exception.started").is_file(), (
        "the worker never recorded that it started")


def test_an_ordinary_scan_is_not_reported_as_a_fault(tmp_path):
    """The other half of the control: no fault record, no fault."""
    run_dir = tmp_path / "clean"
    run_dir.mkdir()
    completed = subprocess.run(
        [sys.executable, str(pathlib.Path(fault_dispatch.__file__)),
         "--run-dir", str(run_dir), "--channel", "api_response"],
        input=HELD.encode(), capture_output=True)

    assert b"GATE2 synthetic scanner exception" not in completed.stderr
    assert not (run_dir / "fault.exception.started").exists()
