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


# ── round 2: what --verify is allowed to certify, and what it may claim ──────
# Round 1 reused the pretty printer's "skip a line I cannot parse" and then
# printed "No orphans. Every evaluation that started also finished." over a file
# whose ONLY line was a 31-byte truncated fragment, exit 0. A checker that
# cannot read a line has to say so.

def _verify(home):
    """Run the real CLI the way a user does, and return (exit code, plain text)."""
    import re as _re
    env = dict(os.environ, SUNGLASSES_HOME=str(home))
    proc = subprocess.run([sys.executable, "-m", "sunglasses.cli", "receipts", "--verify"],
                          cwd=TREE, capture_output=True, text=True, env=env)
    return proc.returncode, _re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout + proc.stderr)


def _write(home, name, text):
    d = home / "receipts"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(text)
    return d / name


def test_a_truncated_final_line_is_reported_and_the_run_is_not_clean(home):
    """The ENOSPC shape: the write died mid-line, so the file ends in a fragment."""
    _write(home, "receipts-2026-09-12.jsonl", '{"kind":"in_flight","eval_id":"a')
    code, out = _verify(home)
    assert code != 0, "a file that cannot be read must not exit 0"
    assert "No orphans" not in out, "an unreadable file was certified clean"
    assert "receipts-2026-09-12.jsonl:1" in out, f"the bad line was not located: {out}"
    assert "INCOMPLETE" in out.upper()


def test_valid_rows_are_still_analysed_alongside_an_unreadable_one(home):
    """Counting the bad line must not throw away the good ones."""
    _write(home, "r.jsonl",
           '{"kind":"in_flight","eval_id":"ok","ts":"t","tool_name":"Bash"}\n'
           '{"kind":"decision","eval_id":"ok"}\n'
           '{"kind":"in_flight","eval_id":"tr')
    code, out = _verify(home)
    assert code != 0
    assert "evaluations started   1" in out, out
    assert "decisions recorded    1" in out, out
    assert "unreadable lines" in out


def test_a_clean_paired_file_is_still_clean(home):
    _write(home, "r.jsonl",
           '{"kind":"in_flight","eval_id":"x","ts":"t","tool_name":"Bash"}\n'
           '{"kind":"decision","eval_id":"x"}\n')
    code, out = _verify(home)
    assert code == 0 and "No orphans" in out, out


# R2. An unmatched opening record proves the PAIR is incomplete. It does not
# prove the tool call ran. Two real cases produce it and neither ran unchecked:
# a hook still blocked on a slow read that then completes normally, and a DENY
# that was decided and enforced whose terminal append hit a full disk.

def test_an_unmatched_opening_does_not_claim_the_tool_call_ran(home):
    _write(home, "r.jsonl",
           '{"kind":"in_flight","eval_id":"y","ts":"t","tool_name":"Bash"}\n')
    code, out = _verify(home)
    assert code != 0
    assert "no terminal partner" in out, out
    lowered = out.lower()
    assert "proceeded unchecked" not in lowered, (
        "the report asserts the host executed the call, which this file cannot show"
    )
    for cause in ("still running", "killed", "terminal append failed"):
        assert cause in lowered, f"the report does not offer the cause {cause!r}: {out}"


def test_a_live_evaluation_looks_the_same_as_a_killed_one_and_is_not_called_dead(home):
    """The hook is still running: opening written, terminal not yet."""
    _write(home, "r.jsonl",
           '{"kind":"in_flight","eval_id":"live","ts":"t","tool_name":"Read"}\n')
    code, out = _verify(home)
    assert code != 0
    assert "still running" in out.lower()
    # ...and once it finishes, the same file is clean.
    _write(home, "r.jsonl",
           '{"kind":"in_flight","eval_id":"live","ts":"t","tool_name":"Read"}\n'
           '{"kind":"decision","eval_id":"live","decision":"allow"}\n')
    code, out = _verify(home)
    assert code == 0, "a completed evaluation must stop being reported"


def test_a_denied_call_whose_terminal_write_failed_is_not_reported_as_unchecked(home):
    """The decision was made and ENFORCED; only the second append was lost."""
    _write(home, "r.jsonl",
           '{"kind":"in_flight","eval_id":"deny1","ts":"t","tool_name":"Bash"}\n')
    code, out = _verify(home)
    assert code != 0
    assert "terminal append failed" in out.lower(), (
        "a DENY that was enforced but could not record itself must be offered "
        "as one of the causes, or the report defames a working block"
    )
