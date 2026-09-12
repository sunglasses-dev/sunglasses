"""
test_receipt_lifecycle.py — THE FAILURE THAT WROTE NOTHING AT ALL.

The README said every fail-open writes a receipt saying the call was not
checked. That was false for the failure that matters most. When the harness
kills a PreToolUse hook on its timeout, the call proceeds unchecked and NOTHING
runs to write the receipt, so the audit trail is silent. Silence is also what a
hook that was never installed looks like, so the two were indistinguishable.

Proven, not assumed: a hook process that dies during evaluation leaves exactly
one record. Before this change it left zero.

The fix writes the evidence BEFORE the work. An `in_flight` record is appended
the moment a call arrives, carrying an evaluation id, and the terminal record
references it. A killed evaluation leaves an orphan and
`sunglasses receipts --verify` names it.

This does not make the hook fail closed. The harness owns that contract. It
makes the failure legible.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

import pytest

from sunglasses.cli import _verify_lifecycle
from sunglasses.firewall import run_hook

TREE = pathlib.Path(__file__).resolve().parents[1]
PAYLOAD = json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "echo hello"},
    "session_id": "lifecycle-test",
})


def _records(home):
    return [json.loads(line)
            for f in sorted((home / "receipts").glob("*.jsonl"))
            for line in f.read_text().splitlines() if line.strip()]


@pytest.fixture
def home(tmp_path):
    return tmp_path / "sunglasses-home"


def test_a_completed_call_writes_an_opening_and_a_terminal_record(home):
    run_hook(PAYLOAD, home=home)
    recs = _records(home)
    kinds = [r.get("kind") for r in recs]
    assert kinds == ["in_flight", "decision"], f"expected a pair, got {kinds}"
    assert recs[0]["eval_id"] == recs[1]["eval_id"], "the pair must share one evaluation id"
    assert recs[0]["tool_name"] == recs[1]["tool_name"] == "Bash"


def test_the_opening_record_is_written_before_the_decision_is_known(home):
    run_hook(PAYLOAD, home=home)
    opening = _records(home)[0]
    assert "decision" not in opening, (
        "the opening record must not claim a verdict; its whole purpose is to exist "
        "before one is reached"
    )


def test_the_opening_record_never_carries_the_tool_input(home):
    run_hook(json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": "echo SUPERSECRETVALUE"}, "session_id": "s",
    }), home=home)
    blob = json.dumps(_records(home))
    assert "SUPERSECRETVALUE" not in blob, (
        "an audit line that quotes the payload becomes the leak it was meant to record"
    )


def test_a_call_killed_during_evaluation_leaves_exactly_one_orphan(tmp_path):
    """The real failure, reproduced in a real process.

    `os._exit(137)` during evaluate() is what the harness's kill leaves behind:
    no unwinding, no finally, no terminal record.
    """
    home = tmp_path / "home"
    victim = tmp_path / "victim.py"
    victim.write_text(
        "import os, sys, json, pathlib\n"
        f"sys.path.insert(0, {str(TREE)!r})\n"
        "import sunglasses.firewall as fw\n"
        "fw.evaluate = lambda *a, **k: os._exit(137)\n"
        f"fw.run_hook({PAYLOAD!r}, home=pathlib.Path({str(home)!r}))\n"
    )
    proc = subprocess.run([sys.executable, str(victim)], capture_output=True)
    assert proc.returncode == 137, f"the victim should die mid-evaluation, got {proc.returncode}"

    recs = _records(home)
    assert len(recs) == 1 and recs[0]["kind"] == "in_flight", (
        f"a killed evaluation must leave its opening record and nothing else, got {recs}"
    )
    assert _verify_lifecycle(recs, home / "receipts") == 1, (
        "the verifier must FAIL on an orphan; an unchecked call is not an OK state"
    )


def test_control_without_the_opening_record_a_killed_call_is_invisible(tmp_path):
    """The mutation: this is the world before the change.

    With no opening record the same kill leaves an EMPTY trail, and the verifier
    has nothing to report. That is the defect, and it is why the opening record
    cannot be made conditional or best-effort-skipped later.
    """
    home = tmp_path / "home"
    victim = tmp_path / "victim.py"
    victim.write_text(
        "import os, sys, json, pathlib\n"
        f"sys.path.insert(0, {str(TREE)!r})\n"
        "import sunglasses.firewall as fw\n"
        "_real = fw.write_receipt\n"
        "fw.write_receipt = lambda rec, home=None: None if rec.get('kind') == 'in_flight' "
        "else _real(rec, home=home)\n"
        "fw.evaluate = lambda *a, **k: os._exit(137)\n"
        f"fw.run_hook({PAYLOAD!r}, home=pathlib.Path({str(home)!r}))\n"
    )
    proc = subprocess.run([sys.executable, str(victim)], capture_output=True)
    assert proc.returncode == 137
    recs = _records(home)
    assert recs == [], f"without the opening record the kill leaves no trace, got {recs}"
    assert _verify_lifecycle(recs, home / "receipts") == 0, (
        "and the verifier reports nothing wrong, which is exactly the blindness fixed here"
    )


def test_legacy_lines_are_not_reported_as_orphans(home):
    """Receipts written before this existed carry no `kind`.

    They are terminal records by definition. Counting them as orphans would fill
    every existing user's verifier output with false alarms on their first run,
    and a report that is mostly noise gets ignored.
    """
    legacy = [{"ts": "2026-09-01T00:00:00-07:00", "tool_name": "Bash", "decision": "allow"},
              {"ts": "2026-09-01T00:00:01-07:00", "tool_name": "Read", "decision": "deny"}]
    assert _verify_lifecycle(legacy, home) == 0


def test_a_clean_trail_passes(home):
    for _ in range(3):
        run_hook(PAYLOAD, home=home)
    assert _verify_lifecycle(_records(home), home / "receipts") == 0


def test_orphans_are_found_among_completed_calls(home):
    """One bad call in a healthy trail must still be named."""
    run_hook(PAYLOAD, home=home)
    recs = _records(home)
    recs.append({"ts": "2026-09-11T20:00:00-07:00", "kind": "in_flight",
                 "eval_id": "deadbeefdeadbeef", "tool_name": "Write"})
    run_hook(PAYLOAD, home=home)
    recs += _records(home)[2:]
    assert _verify_lifecycle(recs, home / "receipts") == 1
