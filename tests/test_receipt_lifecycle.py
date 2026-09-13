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
import ast
import json
import os
import pathlib
import subprocess
import sys
import textwrap
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


# ── round 3: a write cut inside a character must not take the file down ──────
# Round 2 counted lines it could not PARSE. It still read the file with
# `read_text()`, which decodes the whole thing at once, so a single truncated
# multibyte character anywhere in it raised and the command analysed NOTHING —
# a traceback instead of a report. The reviewer's artifact is exactly that: a
# DENY whose terminal record was cut mid-character when the process died.
#
# Receipts are now read as BYTES and decoded one line at a time. An undecodable
# line is counted and located; it is never decoded with errors="replace" and
# then accepted, because a line rebuilt out of substitution characters is not
# the line that was written.

BYTE_FIXTURES = pathlib.Path(__file__).resolve().parent / "receipt_byte_fixtures"
REVIEWER_ARTIFACT = BYTE_FIXTURES / "reviewer_partial_utf8.jsonl"
GOOD = b'{"kind": "in_flight", "eval_id": "ok1", "ts": "t", "tool_name": "Bash"}'
DONE = b'{"kind": "decision", "eval_id": "ok1", "decision": "allow"}'
CUT = b'{"ts": "2026-09-12", "kind": "decision", "session_id": "review-\xe2\x82'


def _write_bytes_file(home, name, data):
    d = home / "receipts"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data)
    return d / name


def test_the_reviewer_artifact_really_is_undecodable_as_a_whole():
    """Guard the fixture itself: if it ever decodes, it stopped being the case."""
    raw = REVIEWER_ARTIFACT.read_bytes()
    with pytest.raises(UnicodeDecodeError):
        raw.decode("utf-8")


def test_the_reviewer_artifact_reports_instead_of_crashing(home):
    _write_bytes_file(home, "2026-09-12.jsonl", REVIEWER_ARTIFACT.read_bytes())
    code, out = _verify(home)
    assert "Traceback" not in out, f"the command crashed instead of reporting:\n{out}"
    assert code != 0
    assert "2026-09-12.jsonl:4" in out, f"the cut line was not located: {out}"
    assert "INCOMPLETE" in out.upper()


def test_a_cut_in_the_middle_still_leaves_the_lines_around_it_analysed(home):
    _write_bytes_file(home, "mid.jsonl", GOOD + b"\n" + CUT + b"\n" + DONE + b"\n")
    code, out = _verify(home)
    assert code != 0
    assert "mid.jsonl:2" in out, out
    # the valid rows either side are still counted
    assert "evaluations started   1" in out, out
    assert "decisions recorded    1" in out, out


def test_one_broken_file_does_not_silence_a_clean_one(home):
    _write_bytes_file(home, "a-clean.jsonl", GOOD + b"\n" + DONE + b"\n")
    _write_bytes_file(home, "b-broken.jsonl", CUT + b"\n")
    code, out = _verify(home)
    assert code != 0
    assert "b-broken.jsonl:1" in out, out
    assert "evaluations started   1" in out, "the clean file stopped being read"


def test_an_undecodable_line_is_never_rebuilt_with_replacement_characters(home):
    _write_bytes_file(home, "r.jsonl", CUT + b"\n")
    code, out = _verify(home)
    assert "�" not in out, (
        "the report contains U+FFFD, so a line was decoded with replacement and "
        "shown as if it were what was written"
    )


def test_control_reading_the_whole_file_at_once_brings_the_crash_back():
    """The mutation: `read_text()` is what could not survive this file."""
    with pytest.raises(UnicodeDecodeError):
        REVIEWER_ARTIFACT.read_text()


# ── round 4: a preview may not repaint the display it is evidence for ────────
# ASTRA R3-1. Round 3 removed the quoting on the malformed-JSON branch because
# "raw already carries its own quoting" — true of the decode branch, which
# builds a byte preview, and false of this one, which stored the decoded line as
# it stood. So a receipts line that is valid UTF-8 and invalid JSON reached the
# terminal verbatim, and `ESC [2J ESC [H ALL CLEAR - 0 threats` erased the
# incomplete-run diagnostic printed immediately above it. The report still said
# INCOMPLETE and still exited 1; the user just could not see it any more.
#
# These assertions are on the RAW stdout BYTES. `_verify` above strips SGR
# before any test sees the output, which is precisely the kind of help that
# would have hidden this: the bug WAS an escape sequence in the output.

import re as _re
import unicodedata as _unicodedata

_SGR = _re.compile(rb"\x1b\[[0-9;]*m")

# The exact controls ASTRA replayed through a persisted receipt.
_RECEIPT_CONTROLS = (
    ("NUL", b"\x00"),
    ("screen erase ESC [2J", b"\x1b[2J"),
    ("cursor home ESC [H", b"\x1b[H"),
    ("carriage return", b"\r"),
    ("C1 CSI U+009B", "".encode("utf-8")),
    ("bidi override U+202E", "‮".encode("utf-8")),
)

# Valid UTF-8, invalid JSON, carrying every control in the list above.
HOSTILE_TEXT = (
    '{"kind": "decision", "eval_id": "x"\x00'
    ' \x1b[2J\x1b[H ALL CLEAR - 0 threats\r‮'
)
# The same line cut mid-character, so it never decodes: the other branch.
HOSTILE_BYTES = HOSTILE_TEXT.encode("utf-8") + b"\xe2\x82"


def _verify_raw(home, mutate=None):
    """Run the real CLI and return (exit code, the BYTES a terminal receives)."""
    env = dict(os.environ, SUNGLASSES_HOME=str(home))
    if mutate is None:
        argv = [sys.executable, "-m", "sunglasses.cli", "receipts", "--verify"]
    else:
        argv = [sys.executable, "-c", mutate]
    proc = subprocess.run(argv, cwd=TREE, capture_output=True, env=env)
    return proc.returncode, proc.stdout + proc.stderr


def _assert_inert(raw: bytes):
    """Nothing the receipt supplied may act on the terminal."""
    for name, sequence in _RECEIPT_CONTROLS:
        assert sequence not in raw, f"the receipt's {name} reached stdout as bytes"
    # And the general statement, so a control nobody thought to list is caught
    # too: the only escapes this command emits are its own colour codes, so with
    # those removed no control or format character may remain except newline.
    rest = _SGR.sub(b"", raw)
    leftover = sorted({
        f"U+{ord(c):04X}" for c in rest.decode("utf-8", "replace")
        if c != "\n" and _unicodedata.category(c) in ("Cc", "Cf")
    })
    assert not leftover, f"control/format characters reached stdout: {leftover}"


def _plain(raw: bytes) -> str:
    return _SGR.sub(b"", raw).decode("utf-8", "replace")


def test_a_malformed_json_receipt_line_cannot_repaint_the_terminal(home):
    _write_bytes_file(home, "2026-09-12.jsonl",
                      GOOD + b"\n" + DONE + b"\n" + HOSTILE_TEXT.encode("utf-8") + b"\n")
    code, raw = _verify_raw(home)
    _assert_inert(raw)
    out = _plain(raw)
    assert code == 1, out
    assert "2026-09-12.jsonl:3" in out, f"the bad line was not located: {out}"
    assert "evaluations started   1" in out, out
    assert "decisions recorded    1" in out, out
    assert "INCOMPLETE" in out.upper(), out


def test_an_undecodable_receipt_line_cannot_repaint_the_terminal(home):
    """The other branch, same bytes: the two may not diverge again."""
    _write_bytes_file(home, "2026-09-12.jsonl",
                      GOOD + b"\n" + DONE + b"\n" + HOSTILE_BYTES + b"\n")
    code, raw = _verify_raw(home)
    _assert_inert(raw)
    out = _plain(raw)
    assert code == 1, out
    assert "2026-09-12.jsonl:3" in out, f"the bad line was not located: {out}"
    assert "evaluations started   1" in out, out
    assert "decisions recorded    1" in out, out
    assert "INCOMPLETE" in out.upper(), out


# The mutation, kept in the suite rather than run once by hand: put round 3's
# behaviour back — the decoded line stored as it stands — and the malformed-JSON
# case must replay its controls again. If this ever stops failing, the quoting
# path stopped being what protects the display.
_ROUND3_BEHAVIOUR = (
    "import sys, types;"
    "from sunglasses import cli;"
    "cli._unreadable_preview = ("
    "  lambda material, reason='':"
    "  material if isinstance(material, str) else repr(material));"
    "sys.exit(cli.cmd_receipts("
    "  types.SimpleNamespace(verify=True, today=False, limit=40)))"
)


def test_control_the_round_3_preview_replays_the_controls(home):
    _write_bytes_file(home, "2026-09-12.jsonl",
                      GOOD + b"\n" + DONE + b"\n" + HOSTILE_TEXT.encode("utf-8") + b"\n")
    code, raw = _verify_raw(home, mutate=_ROUND3_BEHAVIOUR)
    assert code == 1, _plain(raw)
    replayed = [name for name, sequence in _RECEIPT_CONTROLS if sequence in raw]
    assert "screen erase ESC [2J" in replayed, (
        "the control did not reproduce the round 3 bug, so the passing tests "
        f"above prove nothing; replayed: {replayed}\n{_plain(raw)}"
    )


def test_control_the_undecodable_branch_also_needs_the_quoting_path(home):
    """Round 3's decode branch was safe by accident of repr, not by contract."""
    _write_bytes_file(home, "2026-09-12.jsonl",
                      GOOD + b"\n" + DONE + b"\n" + HOSTILE_BYTES + b"\n")
    code, raw = _verify_raw(home, mutate=(
        "import sys, types;"
        "from sunglasses import cli;"
        "cli._unreadable_preview = ("
        "  lambda material, reason='':"
        "  material.decode('utf-8', 'replace')"
        "  if isinstance(material, bytes) else material);"
        "sys.exit(cli.cmd_receipts("
        "  types.SimpleNamespace(verify=True, today=False, limit=40)))"
    ))
    assert code == 1, _plain(raw)
    replayed = [name for name, sequence in _RECEIPT_CONTROLS if sequence in raw]
    assert "screen erase ESC [2J" in replayed, (
        f"the decode branch did not replay its controls; replayed: {replayed}"
    )


# ── round 5: valid rows reach the terminal too ───────────────────────────────
# Round 4 fixed the unreadable-line preview and then said the shared sanitizer
# was "the same function every other untrusted field on this render path goes
# through". It was not. A VALID JSON opening row whose `eval_id` is
# `ESC [2J ESC [H ALL CLEAR - 0 threats U+202E` parses perfectly, never touches
# `_unreadable_preview`, and the orphan line printed it verbatim. Naming a gate
# is not putting something through it, which is the same lesson as round 4's,
# one field over.
#
# The lone-surrogate case is the other half and it is why repr is the guard
# rather than the sanitizer: `"tool_name": "mcp__tool\ud800tail"` is valid JSON,
# the sanitizer leaves the surrogate untouched, and `print` then raises
# UnicodeEncodeError and dumps a traceback INSTEAD of naming the orphan the
# command was asked about.

ESC_ERASE = b"\x1b[2J"
CURSOR_HOME = b"\x1b[H"
RAW_EVAL_ID = "\x1b[2J\x1b[HALL CLEAR - 0 threats‮"
SURROGATE_TOOL = "mcp__tool\ud800tail"


def _pair(eval_id="ok1", tool="Bash"):
    return (
        json.dumps({"ts": "2026-09-12T00:00:00", "kind": "in_flight",
                    "eval_id": eval_id, "tool_name": tool}),
        json.dumps({"ts": "2026-09-12T00:00:00", "kind": "decision",
                    "eval_id": eval_id, "decision": "allow"}),
    )


def _orphan(eval_id, tool="Bash"):
    return json.dumps({"ts": "2026-09-12T00:00:00", "kind": "in_flight",
                       "eval_id": eval_id, "tool_name": tool})


def test_a_valid_row_cannot_repaint_the_orphan_report(home):
    """ASTRA's raw eval_id, as a valid JSON row beside a clean pair."""
    started, decided = _pair()
    _write_bytes_file(home, "2026-09-12.jsonl",
                      (started + "\n" + decided + "\n"
                       + _orphan(RAW_EVAL_ID) + "\n").encode("utf-8"))
    code, raw = _verify_raw(home)
    _assert_inert(raw)
    out = _plain(raw)
    assert code == 1, out
    assert "orphan" in out, out
    assert "evaluations started   2" in out, out
    assert "decisions recorded    1" in out, out


def test_a_lone_surrogate_tool_name_is_named_not_a_traceback(home):
    """Valid JSON, unencodable text. The report must still identify the orphan."""
    started, decided = _pair()
    _write_bytes_file(home, "2026-09-12.jsonl",
                      (started + "\n" + decided + "\n"
                       + _orphan("orphan1", SURROGATE_TOOL) + "\n").encode("utf-8"))
    env = dict(os.environ, SUNGLASSES_HOME=str(home))
    proc = subprocess.run(
        [sys.executable, "-m", "sunglasses.cli", "receipts", "--verify"],
        cwd=TREE, capture_output=True, env=env)
    assert b"Traceback" not in proc.stderr + proc.stdout, (
        proc.stderr.decode("utf-8", "replace"))
    assert proc.stderr == b"", proc.stderr
    assert proc.returncode == 1
    out = _plain(proc.stdout)
    assert "orphan" in out and "orphan1" in out, out
    assert "mcp__tool" in out, "the orphan was not identifiable"
    _assert_inert(proc.stdout)


def test_the_pretty_table_survives_the_same_two_rows(home):
    """Not only `--verify`. The default render is the same boundary, and both of
    these predate this PR: the table sanitized its fields, which strips a control
    and leaves a surrogate, and the summary line sanitized nothing at all."""
    rows = [
        json.dumps({"ts": "2026-09-12T00:00:00", "kind": "decision",
                    "eval_id": "a", "decision": "allow", "tool_name": SURROGATE_TOOL}),
        json.dumps({"ts": "2026-09-12T00:00:00", "kind": "decision",
                    "eval_id": "b", "decision": RAW_EVAL_ID, "tool_name": "Bash"}),
    ]
    _write_bytes_file(home, "2026-09-12.jsonl", ("\n".join(rows) + "\n").encode("utf-8"))
    env = dict(os.environ, SUNGLASSES_HOME=str(home))
    proc = subprocess.run([sys.executable, "-m", "sunglasses.cli", "receipts"],
                          cwd=TREE, capture_output=True, env=env)
    assert b"Traceback" not in proc.stdout + proc.stderr, (
        proc.stderr.decode("utf-8", "replace"))
    _assert_inert(proc.stdout + proc.stderr)


@pytest.mark.parametrize("field,value", [
    ("eval_id", RAW_EVAL_ID),
    ("tool_name", SURROGATE_TOOL),
])
def test_control_restoring_the_raw_interpolation_replays_it(home, field, value):
    """The mutation, in the suite. Put the round-4 renderer back for one field
    and the bytes reach stdout again, or the tests above prove nothing."""
    started, decided = _pair()
    row = {"ts": "2026-09-12T00:00:00", "kind": "in_flight", "eval_id": "orphan1",
           "tool_name": "Bash"}
    row[field] = value
    _write_bytes_file(home, "2026-09-12.jsonl",
                      (started + "\n" + decided + "\n"
                       + json.dumps(row) + "\n").encode("utf-8"))
    mutation = (
        "import sys, types;"
        "from sunglasses import cli;"
        "cli._display = lambda value, limit=96: "
        "  '' if value is None else (value if isinstance(value, str) else str(value));"
        "sys.exit(cli.cmd_receipts("
        "  types.SimpleNamespace(verify=True, today=False, limit=40)))"
    )
    code, raw = _verify_raw(home, mutate=mutation)
    if field == "eval_id":
        assert ESC_ERASE in raw and CURSOR_HOME in raw, (
            "the raw eval_id did not replay its controls, so the assertion "
            "above is not what is stopping them")
    else:
        assert b"Traceback" in raw, (
            "the raw surrogate tool name did not crash the renderer, so repr "
            "is not what is keeping the orphan identifiable")


# ── the per-site runtime matrix: the gate ────────────────────────────────────
# Round 6 proved the helper is correct and that removing it GLOBALLY replays the
# bytes. Neither statement says every display site calls it. The reviewer put
# ONE site back to raw, the pretty table's timestamp, and all 433 selected tests
# stayed green: the timestamp is assigned through `str(...)` and a `[11:19]`
# slice, so the source guard below never taints it, and no fixture put hostile
# bytes inside those eight characters. A global mutation cannot find a site that
# is missing; only a per-site one can.
#
# So every display site on this path is listed here BY ITS SOURCE TEXT, each
# with a fixture that puts terminal-control bytes and a lone surrogate inside
# the slice that site actually displays, and each with a restore control that
# puts that ONE call back to raw and must go red by itself. The list is the
# claim: `test_the_matrix_covers_every_display_site` compares it against the
# `_display(` calls in the file, so a new site added tomorrow fails here rather
# than shipping unproven.

# site -> (exact source text, that same call put back to raw)
_SITE_RESTORES = {
    "orphan_ts": ("_display(rec.get('ts'), 32)",
                  "str(rec.get('ts', ''))"),
    "orphan_tool": ("_display(rec.get('tool_name'), 48)",
                    "str(rec.get('tool_name', ''))"),
    "orphan_eval_id": ("_display(eid, 64)",
                       "str(eid)"),
    "pretty_decision": ('decision = _display(row.get("decision", "?"), limit=10)',
                        'decision = str(row.get("decision", "?"))'),
    "pretty_ts": ('stamp = _display(str(row.get("ts", ""))[11:19], limit=8)',
                  'stamp = str(row.get("ts", ""))[11:19]'),
    "pretty_rule_id": ('note = _display(row.get("rule_id", ""), limit=44)',
                       'note = str(row.get("rule_id", ""))'),
    "pretty_error": ('note = _display(row.get("error", "error"), limit=44)',
                     'note = str(row.get("error", "error"))'),
    "pretty_tool": ('tool = _display(row.get("tool_name"), limit=24) or "-"',
                    'tool = str(row.get("tool_name", "")) or "-"'),
    "pretty_lane": ("_display(row.get('lane', ''), limit=13)",
                    "str(row.get('lane', ''))"),
    "summary_decision": ("_display(k, 10)", "str(k)"),
}

# Every payload carries an erase, a cursor home and a bidi override, which is
# what a receipt would use to rewrite the audit line above it, and separately a
# LONE SURROGATE, which no sanitizer removes and which makes `print` raise
# instead of naming what it was asked about.
_CONTROL_PAYLOAD = "\x1b[2J\x1b[H\u202e"
_SURROGATE_PAYLOAD = "\ud800tail"
_PAYLOADS = {"control": _CONTROL_PAYLOAD, "surrogate": _SURROGATE_PAYLOAD}


def _clean_decision(**over):
    row = {"ts": "2026-09-12T00:00:00", "kind": "decision", "eval_id": "clean",
           "decision": "allow", "tool_name": "Bash", "rule_id": "GLS-OK-001",
           "lane": "fast"}
    row.update(over)
    return row


def _fixture(site, payload):
    """(rows, verify) for one site, with `payload` inside the DISPLAYED slice."""
    if site.startswith("orphan_"):
        started, decided = _pair()
        field = {"orphan_ts": "ts", "orphan_tool": "tool_name",
                 "orphan_eval_id": "eval_id"}[site]
        orphan = {"ts": "2026-09-12T00:00:00", "kind": "in_flight",
                  "eval_id": "orphan1", "tool_name": "Bash"}
        orphan[field] = payload + "x"
        return [started, decided, json.dumps(orphan)], True
    if site == "pretty_ts":
        # The displayed slice is characters 11 to 18 of `ts`, so the payload has
        # to live THERE. A payload at the front of the field is exactly what the
        # round-6 fixtures did, and it is why this site was never covered.
        stamp = "2026-09-12T" + payload
        assert payload in stamp[11:19] or stamp[11:19].startswith(payload[:8]), stamp[11:19]
        return [json.dumps(_clean_decision(ts=stamp))], False
    if site == "pretty_error":
        return [json.dumps(_clean_decision(lane="error", error=payload + "x"))], False
    field = {"pretty_decision": "decision", "pretty_rule_id": "rule_id",
             "pretty_tool": "tool_name", "pretty_lane": "lane",
             "summary_decision": "decision"}[site]
    return [json.dumps(_clean_decision(**{field: payload + "x"}))], False


def _run_cli(home, verify, restore=None):
    """The real CLI in a subprocess, with at most ONE display site put to raw."""
    prelude = "import pathlib, sys, types\nfrom sunglasses import cli\n"
    if restore is not None:
        old, new = _SITE_RESTORES[restore]
        prelude += (
            "src = pathlib.Path(cli.__file__).read_text()\n"
            f"old, new = {old!r}, {new!r}\n"
            "assert src.count(old) == 1, (old, src.count(old))\n"
            "exec(compile(src.replace(old, new), cli.__file__, 'exec'), cli.__dict__)\n"
        )
    code = prelude + (
        f"sys.exit(cli.cmd_receipts(types.SimpleNamespace("
        f"verify={verify!r}, today=False, limit=40)))\n"
    )
    env = dict(os.environ, SUNGLASSES_HOME=str(home))
    proc = subprocess.run([sys.executable, "-c", code], cwd=TREE,
                          capture_output=True, env=env)
    return proc.returncode, proc.stdout + proc.stderr


def _write_rows(home, rows):
    _write_bytes_file(home, "2026-09-12.jsonl",
                      ("\n".join(rows) + "\n").encode("utf-8", "surrogatepass"))


def test_what_the_gate_actually_leaves_behind_over_every_code_point():
    """The corrected docstring sentence, as an assertion.

    Rounds 4 to 6 said the sanitizer behind repr is a no-op "on repr's ASCII
    output". Repr's output is NOT ASCII: it keeps printable non-ASCII as itself.
    The claim that holds is about CATEGORIES, so that is what is checked, over
    every code point rather than over a sample. Takes about a second.
    """
    from sunglasses.cli import _display

    dangerous, nonascii = [], 0
    for cp in range(0x110000):
        out = _display(chr(cp))
        for ch in out:
            if _unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Zl", "Zp"):
                dangerous.append((hex(cp), hex(ord(ch))))
            if ord(ch) > 0x7F:
                nonascii += 1
    assert dangerous == [], dangerous[:10]
    assert nonascii > 0, (
        "every output character is ASCII after all, so the docstring's old "
        "sentence was right and this correction should be reverted")


def test_the_matrix_covers_every_display_site():
    """The list is a claim about the file, so the file is what checks it.

    A `_display(` call that nobody added a row for is a site with no fixture and
    no restore control, which is precisely the state the pretty timestamp was in.
    """
    source = (TREE / "sunglasses" / "cli.py").read_text()
    calls = [line.strip() for line in source.splitlines()
             if "_display(" in line and not line.strip().startswith(("#", "*"))
             and "def _display" not in line]
    # every listed site must appear exactly once, and the counts must agree
    for site, (old, _new) in _SITE_RESTORES.items():
        assert source.count(old) == 1, (site, source.count(old))
    listed = sum(old.count("_display(") for old, _ in _SITE_RESTORES.values())
    found = sum(line.count("_display(") for line in calls)
    assert found == listed, (
        f"cli.py makes {found} `_display` calls on this path and the matrix "
        f"lists {listed}. A display site without a row here has no fixture and "
        f"no restore control.\n  " + "\n  ".join(calls))


@pytest.mark.parametrize("payload", sorted(_PAYLOADS), ids=sorted(_PAYLOADS))
@pytest.mark.parametrize("site", sorted(_SITE_RESTORES), ids=sorted(_SITE_RESTORES))
def test_no_display_site_lets_receipt_bytes_reach_the_terminal(home, site, payload):
    """Twenty runtime assertions: ten sites, control bytes and a lone surrogate."""
    rows, verify = _fixture(site, _PAYLOADS[payload])
    _write_rows(home, rows)
    _code, raw = _run_cli(home, verify)
    assert b"Traceback" not in raw, raw.decode("utf-8", "replace")
    _assert_inert(raw)


@pytest.mark.parametrize("payload", sorted(_PAYLOADS), ids=sorted(_PAYLOADS))
@pytest.mark.parametrize("site", sorted(_SITE_RESTORES), ids=sorted(_SITE_RESTORES))
def test_control_restoring_one_site_replays_it(home, site, payload):
    """And each of the twenty goes red on its own when that ONE call is raw.

    Not the helper globally. The reviewer's finding was a site the global
    mutation could not distinguish from a covered one.
    """
    rows, verify = _fixture(site, _PAYLOADS[payload])
    _write_rows(home, rows)
    _code, raw = _run_cli(home, verify, restore=site)
    if payload == "control":
        assert ESC_ERASE in raw and CURSOR_HOME in raw, (
            f"{site}: restoring this one call did not replay its controls, so "
            f"the assertion above is not what is stopping them.\n"
            + raw.decode("utf-8", "replace"))
    else:
        assert b"Traceback" in raw, (
            f"{site}: restoring this one call did not crash on the lone "
            f"surrogate, so repr is not what is keeping this field printable.\n"
            + raw.decode("utf-8", "replace"))


# ── the source-reading SMOKE CHECK, and what it does not claim ───────────────
# Round 5 shipped this as a line grep for `{...get(` inside an f-string, and it
# caught one of eight shapes. Round 6 replaced it with an AST walk that caught
# all eight and then claimed, by its name, that no parsed field reaches stdout
# without a gate. The reviewer put 29 more shapes to it and 24 escaped: wrapped
# assignment, tuple and dict unpacking, comprehensions, a saved generator, an
# alias to stderr, a class method, subscript access, the walrus, and the
# dict-literal exemption six different ways.
#
# So this stops claiming to be the proof. THE PROOF IS THE RUNTIME MATRIX
# ABOVE: ten display sites, hostile bytes inside the slice each one displays,
# and a per-site restore that goes red on its own. This is a smoke check with a
# narrow claim it can keep: within one function, a `.get` call interpolated
# DIRECTLY into a sink argument, and a local assigned DIRECTLY from one. It is
# here to catch the careless case in review, not to certify the file.
#
# Two things the reviewer got past it are gone rather than documented. The
# dict-literal exemption trusted any `.get` on any name bound to a dict literal,
# which is six lines of setup to defeat; it is replaced by an allowlist of exact
# source lines, currently one. And a gate was trusted by NAME, so a method
# merely called `_display` counted; a gate must now be a bare call to a name
# this module resolves to the real function.

_GATES = {"_display", "_unreadable_preview"}
_SINKS = {"print"}


# Exact source lines this check is allowed to pass, each with the reason. An
# allowlist of LINES, not of a syntax: the previous exemption was "any `.get` on
# a name bound to a dict literal", which the reviewer satisfied six ways.
# `test_the_allowlisted_line_is_still_there_and_still_needs_allowlisting` keeps
# this honest in both directions.
_ALLOWED_LINES = {
    'color = colors.get(decision, "")':
        "the renderer's own ANSI table, keyed by a `decision` that has already "
        "been through _display on the line above. Nothing receipt-supplied can "
        "come out of it.",
}


def _reads_a_parsed_field(node):
    return (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get")


def _called_name(node):
    if not isinstance(node, ast.Call):
        return None
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _is_gate_call(node):
    """A gate is a BARE call to one of the gate names, never an attribute.

    `self._display(x)` and `evil._display(x)` are not this module's gate; round
    6 trusted both because it compared the attribute name.
    `test_the_gate_names_resolve_to_the_real_functions` checks that these names
    mean in `cli` what they mean here.
    """
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in _GATES)


def unrouted_fields(source):
    """Direct `.get` interpolation and directly tainted locals. Nothing wider.

    WHAT THIS CATCHES, and the name of the test says only this: inside one
    function, a `.get` call written straight into a sink argument, a local
    assigned straight from a `.get`, and an underscore helper that is not a gate
    appearing in a sink argument.

    WHAT IT DOES NOT CATCH, executed by the reviewer, 24 shapes of 29: an
    assignment wrapped in anything at all (`str(row.get(...))`, a slice, a
    conditional), tuple and dict unpacking, comprehension targets, a generator
    saved and consumed later, an alias bound to `sys.stderr.write`, a method on
    a class, subscript access instead of `.get`, and the walrus. Flow between
    functions is not tracked in either direction.

    The pretty table's timestamp is the worked example and the reason this
    docstring exists: `_display(str(row.get("ts", ""))[11:19], limit=8)` is
    assigned through a conversion and a slice, so removing the gate there leaves
    this check silent. The RUNTIME MATRIX above is what proves that site, and
    every other one.
    """
    tree = ast.parse(textwrap.dedent(source))
    lines = textwrap.dedent(source).splitlines()
    def allowed(where):
        return (1 <= where <= len(lines)
                and lines[where - 1].strip() in _ALLOWED_LINES)
    problems = []
    for func in [n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        tainted = {t.id for node in ast.walk(func)
                   if isinstance(node, ast.Assign)
                   and _reads_a_parsed_field(node.value)
                   and not allowed(getattr(node, "lineno", 0))
                   for t in node.targets if isinstance(t, ast.Name)}
        inside_a_gate = set()
        for parent in ast.walk(func):
            if _is_gate_call(parent):
                inside_a_gate.update(id(n) for n in ast.walk(parent))

        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            sink = _called_name(node)
            is_write = (isinstance(node.func, ast.Attribute)
                        and node.func.attr == "write")
            if sink not in _SINKS and not is_write:
                continue
            for arg in node.args:
                for inner in ast.walk(arg):
                    where = getattr(inner, "lineno", 0)
                    if allowed(where):
                        continue
                    if _reads_a_parsed_field(inner) \
                            and id(inner) not in inside_a_gate:
                        problems.append(
                            f"{func.name}:{where} a parsed field reaches "
                            f"{sink or 'write'}() unwrapped")
                    if isinstance(inner, ast.Name) and inner.id in tainted:
                        problems.append(
                            f"{func.name}:{where} {inner.id!r} holds a parsed "
                            f"field and reaches {sink or 'write'}()")
                    called = _called_name(inner)
                    if called and called.startswith("_") \
                            and called not in _GATES and called not in _SINKS:
                        problems.append(
                            f"{func.name}:{where} helper {called}() feeds "
                            f"{sink or 'write'}() and is not a gate")
    return problems


def test_no_direct_parsed_field_interpolation_reaches_stdout():
    """The narrowed claim: no DIRECT interpolation, in these two functions.

    Not "no parsed field reaches stdout". That sentence belongs to the runtime
    matrix above, which executes every display site.
    """
    import inspect
    from sunglasses import cli

    for function in (cli._verify_lifecycle, cli.cmd_receipts):
        problems = unrouted_fields(inspect.getsource(function))
        assert problems == [], (
            f"{function.__name__} interpolates a parsed field directly without "
            f"routing it through _display:\n  " + "\n  ".join(problems))


def test_the_gate_names_resolve_to_the_real_functions():
    """`_GATES` is a set of strings. This is what makes them mean something."""
    import types
    from sunglasses import cli

    for name in _GATES:
        gate = getattr(cli, name, None)
        assert isinstance(gate, types.FunctionType), f"{name} is {gate!r}"
        assert gate.__module__ == "sunglasses.cli", gate.__module__


def test_the_allowlisted_line_is_still_there_and_still_needs_allowlisting():
    """Both directions, so the allowlist cannot rot into a blanket.

    If the line is gone, the entry is dead and must be deleted. If the line is
    there and the walker would NOT flag it, the entry is doing nothing and hides
    the next real one.
    """
    import inspect
    from sunglasses import cli

    source = inspect.getsource(cli.cmd_receipts)
    for line in _ALLOWED_LINES:
        assert line in source, f"allowlisted line is gone from cli.py: {line!r}"
    saved = dict(_ALLOWED_LINES)
    try:
        _ALLOWED_LINES.clear()
        problems = unrouted_fields(source)
    finally:
        _ALLOWED_LINES.update(saved)
    assert problems, (
        "with the allowlist empty the walker flags nothing, so every entry in "
        "it is decoration")
    assert unrouted_fields(source) == [], unrouted_fields(source)


# Eight ways to print a parsed field. The round 5 grep caught the last one only.
_BYPASSES = {
    "percent format": 'def f(row):\n    print("orphan %s" % row.get("t"))',
    "str.format": 'def f(row):\n    print("orphan {}".format(row.get("e")))',
    "concatenation": 'def f(row):\n    print("orphan " + row.get("t"))',
    "via a local": ('def f(row):\n    name = row.get("t")\n'
                    '    print(f"orphan {name}")'),
    "helper returning raw": 'def f(row):\n    print(f"orphan {_raw(row)}")',
    "join": 'def f(row):\n    print(" ".join(["orphan", row.get("e")]))',
    "stdout.write": 'def f(row):\n    sys.stdout.write(row.get("err"))',
    "plain f-string": 'def f(row):\n    print(f"orphan {row.get(\'e\')}")',
}
_CLEAN = {
    "routed f-string": ('def f(row):\n'
                        '    print(f"orphan {_display(row.get(\'e\'))}")'),
    "routed local": ('def f(row):\n    name = _display(row.get("t"))\n'
                     '    print(f"orphan {name}")'),
    "nothing parsed at all": 'def f(row):\n    print("orphan")',
}
# Round 6 had the shape below in `_CLEAN`, passing because any `.get` on a name
# bound to a dict literal was exempt. That exemption is gone, so this is now a
# FALSE POSITIVE and it is filed as one: asserted flagged, so the cost of
# dropping the exemption is visible rather than discovered, and handled by the
# one line in `_ALLOWED_LINES` rather than by a rule anyone can satisfy.
# Six of the reviewer's 24 escapes, executed. The docstring above states them
# in prose; these make the statement checkable, and they are the reason the
# runtime matrix and not this walker is the gate.
_SHAPES_THAT_ESCAPE = {
    "assignment wrapped in str()":
        'def f(row):\n    t = str(row.get("t"))\n    print(f"orphan {t}")',
    "assignment through a slice":
        'def f(row):\n    t = str(row.get("t"))[11:19]\n    print(f"orphan {t}")',
    "tuple unpacking":
        'def f(row):\n    a, b = row.get("a"), row.get("b")\n    print(f"{a}{b}")',
    "comprehension target":
        'def f(rows):\n    xs = [r.get("t") for r in rows]\n    print(" ".join(xs))',
    "saved generator":
        'def f(rows):\n    g = (r.get("t") for r in rows)\n    print(next(g))',
    # The walrus ESCAPES only when it binds outside the sink: `tainted` is
    # built from ast.Assign and a NamedExpr is not one. Written INSIDE the
    # print argument the `.get` is visible and this walker does catch it, which
    # is why that form is in _BYPASSES and this one is here.
    "walrus binding outside the sink":
        'def f(row):\n    if (t := row.get("t")):\n        print(f"orphan {t}")',
}
_ACCEPTED_FALSE_POSITIVES = {
    "a lookup in the renderer's own dict": (
        'def f(row):\n    colors = {"a": "1"}\n'
        '    c = colors.get("a", "")\n'
        '    print(f"orphan {c}")'),
}


@pytest.mark.parametrize("shape", sorted(_BYPASSES), ids=sorted(_BYPASSES))
def test_control_each_bypass_shape_is_caught(shape):
    """Each one red on its own, or the guard is a grep with extra steps."""
    assert unrouted_fields(_BYPASSES[shape]), (
        f"{shape!r} prints a parsed field and the guard did not see it")


@pytest.mark.parametrize("shape", sorted(_CLEAN), ids=sorted(_CLEAN))
def test_control_a_clean_shape_is_not_flagged(shape):
    """And the other half, because a guard that flags everything protects
    nothing and gets switched off by the first person it annoys."""
    assert unrouted_fields(_CLEAN[shape]) == [], unrouted_fields(_CLEAN[shape])


@pytest.mark.parametrize("shape", sorted(_ACCEPTED_FALSE_POSITIVES),
                         ids=sorted(_ACCEPTED_FALSE_POSITIVES))
def test_the_accepted_false_positive_really_is_flagged(shape):
    """The price of dropping the dict-literal exemption, stated as a fact.

    If this ever stops being flagged, someone has put a category exemption back
    and `_ALLOWED_LINES` is no longer the only way past.
    """
    assert unrouted_fields(_ACCEPTED_FALSE_POSITIVES[shape]), (
        f"{shape!r} is no longer flagged, so an exemption wider than "
        f"_ALLOWED_LINES has come back")


@pytest.mark.parametrize("shape", sorted(_SHAPES_THAT_ESCAPE),
                         ids=sorted(_SHAPES_THAT_ESCAPE))
def test_the_documented_escapes_really_do_escape(shape):
    """The docstring says 24 of the reviewer's 29 shapes get past. Six of them
    are here as executed evidence, because a limit nobody runs is a guess.

    Each of these prints a parsed field and this check stays silent. That is
    the stated behaviour, not a defect to fix here: the runtime matrix is what
    covers the real file.
    """
    assert unrouted_fields(_SHAPES_THAT_ESCAPE[shape]) == [], (
        f"{shape!r} is now caught. Good, but the docstring says it is not; "
        f"move it to _BYPASSES and narrow the paragraph.")
