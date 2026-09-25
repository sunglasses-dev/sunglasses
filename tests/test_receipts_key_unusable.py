"""test_receipts_key_unusable.py — a key that exists but cannot sign is a
receipt failure, never a quiet return to unsigned rows (T9 RULING 21).

The user opted into a signed chain with an explicit `receipts init`. If the key
then cannot be used (a mode that exposes it, the receipts extra removed, a file
that cannot be read) the hook must not go back to unsigned lines on its own:
that is a file shaped like a chain with nothing able to sign it, the hazard the
spec names. Three conditions, one section each.

(a) defer and allow become ask, deny stays deny, and the ask names the cause
    and the one command that clears it.
(b) `receipts --verify` reports KEY_UNUSABLE with the same cause.
(c) `receipts off` is the only road back to unsigned, and it is written as the
    last record of the segment: a close checkpoint when the key still signs,
    otherwise an unsigned row that the verifier reports as unsigned.

doctor.py's half of (b) is left to its owner.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

from sunglasses import firewall
from sunglasses.firewall import Decision, run_hook
from sunglasses.receipts import chain, keys, verify, wire

TREE = pathlib.Path(__file__).resolve().parents[1]
CALL = json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "echo hello"},
    "session_id": "r21-test",
})
EXTRA = "sunglasses[receipts]"
# The receipts extra, gone: the hook's lazy import of the signing code fails.
NO_EXTRA = "import sys; sys.modules['cryptography'] = None\n"


@pytest.fixture
def home(tmp_path):
    """A home that opted in: a key, and one sealed hook call on its chain."""
    home = tmp_path / "sunglasses-home"
    keys.init(home)
    run_hook(CALL, home=home)
    return home


def _key(home):
    return keys.private_path(home)


def _hook_log(home):
    return home / "receipts" / "hook"


def _legacy(home):
    return sorted((home / "receipts").glob("*.jsonl"))


def _segments(home):
    return {p.name: p.read_bytes() for p in _hook_log(home).glob(chain.SEGMENT_GLOB)}


def _decision(out):
    spec = out.get("hookSpecificOutput", {})
    return spec.get("permissionDecision"), spec.get("permissionDecisionReason", "")


def _hook_without_extra(home):
    script = (NO_EXTRA
              + "import json, pathlib\n"
              + "from sunglasses.firewall import run_hook\n"
              + f"print(json.dumps(run_hook({CALL!r}, home=pathlib.Path({str(home)!r}))))\n")
    proc = subprocess.run([sys.executable, "-c", script], cwd=TREE,
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _cli(home, *argv, prelude=""):
    env = {**os.environ, "SUNGLASSES_HOME": str(home), "NO_COLOR": "1"}
    script = (prelude + "import runpy, sys\n"
              + f"sys.argv = ['sunglasses', 'receipts', *{list(argv)!r}]\n"
              + "runpy.run_module('sunglasses.cli', run_name='__main__')\n")
    return subprocess.run([sys.executable, "-c", script], cwd=TREE, env=env,
                          capture_output=True, text=True)


# ── (a) the hook asks, naming the cause and the command ──────────────────────

@pytest.mark.parametrize("mode", [0o644, 0o200], ids=["exposed", "unreadable"])
def test_a_key_with_a_bad_mode_asks_with_the_cause_and_chmod(home, mode):
    path = _key(home)
    os.chmod(path, mode)
    before = _segments(home)
    kind, reason = _decision(run_hook(CALL, home=home))
    assert kind == "ask"
    assert str(path) in reason
    assert "chmod 600" in reason
    assert _legacy(home) == []
    assert _segments(home) == before


def test_the_extra_removed_asks_with_the_cause_and_the_install_command(home):
    before = _segments(home)
    kind, reason = _decision(_hook_without_extra(home))
    assert kind == "ask"
    assert EXTRA in reason
    assert _legacy(home) == []
    assert _segments(home) == before


def test_the_control_a_usable_key_still_defers_and_seals(home):
    """Without this the asks above could be the hook failing on everything."""
    assert run_hook(CALL, home=home) == {}
    assert _legacy(home) == []
    kinds = [wire.decode_strict(line)["event"]
             for data in _segments(home).values()
             for line in data.splitlines(keepends=True)]
    assert kinds.count("decision") == 2


def test_a_deny_stays_a_deny_with_an_unusable_key(home, monkeypatch):
    os.chmod(_key(home), 0o644)
    denied = Decision("deny", "policy", "GLS-FW-R21-TEST", "denied for the test")
    monkeypatch.setattr(firewall, "evaluate", lambda p, home=None: (denied, None, {}))
    kind, _ = _decision(run_hook(CALL, home=home))
    assert kind == "deny"


def test_a_key_removed_under_a_live_chain_asks_and_writes_no_unsigned_row(home):
    """Removing the key file is not `receipts off`. A chain exists, so the user
    opted in; with no key the hook must not quietly start a legacy day file."""
    _key(home).unlink()
    kind, _ = _decision(run_hook(CALL, home=home))
    assert kind == "ask"
    assert _legacy(home) == []


# ── (b) the verifier names it ────────────────────────────────────────────────

def test_verify_reports_key_unusable_with_the_mode_cause(home):
    path = _key(home)
    os.chmod(path, 0o644)
    proc = _cli(home, "--verify")
    out = proc.stdout + proc.stderr
    assert "KEY_UNUSABLE" in out
    assert str(path) in out and "chmod 600" in out


def test_verify_reports_key_unusable_with_the_extra_cause(home):
    proc = _cli(home, "--verify", prelude=NO_EXTRA)
    out = proc.stdout + proc.stderr
    assert "KEY_UNUSABLE" in out
    assert EXTRA in out
    assert proc.returncode != 0


def test_the_control_verify_with_a_usable_key_never_says_key_unusable(home):
    proc = _cli(home, "--verify")
    assert "KEY_UNUSABLE" not in proc.stdout + proc.stderr


# ── (c) `receipts off` is the only road back, and it is on the record ────────

def _last_segment_records(home):
    last = sorted(_hook_log(home).glob(chain.SEGMENT_GLOB))[-1]
    return [wire.decode_strict(line)
            for line in last.read_bytes().splitlines(keepends=True)]


def test_off_with_a_usable_key_is_sealed_as_the_segments_last_record(home):
    proc = _cli(home, "off")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    records = _last_segment_records(home)
    assert records[-1]["event"] == "checkpoint"
    assert records[-1]["purpose"] == "close"
    assert "off" in records[-2]["event"]
    sealed = _segments(home)
    run_hook(CALL, home=home)
    assert len(_legacy(home)) == 1          # unsigned now, because the user said so
    assert _segments(home) == sealed        # and the chain is never written again


def test_off_with_an_unusable_key_is_an_unsigned_last_row_reported_as_such(home):
    os.chmod(_key(home), 0o644)
    proc = _cli(home, "off")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    records = _last_segment_records(home)
    assert records[-1]["event"] != "checkpoint"
    assert "off" in records[-1]["event"]
    fingerprint = next((home / "keys" / "public").glob("*.pub")).stem
    public = keys.public_path(home, fingerprint).read_bytes()
    report = verify.verify_log(_hook_log(home), public, expected_fingerprint=fingerprint)
    assert report.results["unsigned_tail"] != "NO_VISIBLE_TAIL"
