"""test_firewall_secret_lane_down.py — THE SECRET CHECK IS THE CONTROL THAT DIED.

The secret detector needs no configuration, so it is the one control a user
cannot have misconfigured. When it raised, the generic fail-open answered `{}`:
the host's own permission flow, a receipt, and nothing on screen. That is the
right answer for a dead pin lane and the wrong one for a dead secret lane on a
call that may carry a credential.

Now, on that fault only: an outbound call that looks credential-shaped ASKS, and the question says which control
died. Every other call gets the generic `{}` plus a confession in the receipt.
`~/.sunglasses/on-error` picks ask (default) / deny / defer / block.

Key-shaped strings are built by concatenation so this file is not itself a hit.
"""
import io
import json

import pytest

from sunglasses import firewall
from sunglasses.firewall import run_hook, run_hook_ex

AWS = "AKIA" + "ZQXWVUTSRPNMLKJH"
GHP = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vX7zC9eF1hJ3kL5"
PEM = "-----BEGIN RSA " + "PRIVATE KEY-----"


def _call(tool="mcp__ticket__lookup", **tool_input):
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool,
                       "tool_input": tool_input, "session_id": "secret-down"})


def _out(raw):
    o = raw.get("hookSpecificOutput", {})
    return o.get("permissionDecision"), o.get("permissionDecisionReason", "")


def _boom(_text):
    raise RuntimeError("detector exploded on " + AWS)


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "sunglasses-home"
    h.mkdir()
    return h


@pytest.fixture
def dead(monkeypatch):
    monkeypatch.setattr(firewall, "find_secret_material", _boom)


def _chain_text(home):
    return "\n".join(p.read_text(errors="replace") for p in home.rglob("*") if p.is_file())


def _decision_body(home):
    rows = [json.loads(line) for f in sorted((home / "receipts").glob("*.jsonl"))
            for line in f.read_text().splitlines() if line.strip()]
    decisions = [r for r in rows if r.get("kind") == "decision"]
    assert decisions, "no decision record"
    return decisions[-1]


# 1. egress + credential-shaped candidate -> ask; nothing leaks into stdout or receipt
@pytest.mark.parametrize("material", [AWS, GHP, PEM])
def test_dead_detector_on_credential_shaped_egress_asks(home, dead, material):
    raw = run_hook(_call(note="ticket 4 " + material), home=home)
    action, reason = _out(raw)
    assert action == "ask"
    assert "secret detector failed" in reason
    assert "Approve only if you would have approved it unchecked" in reason
    for blob in (json.dumps(raw), _chain_text(home)):
        assert material not in blob
        assert material[8:] not in blob
    body = _decision_body(home)
    assert body["rule_id"] == "GLS-FW-SECRET-DOWN"
    assert body["secret_lane_down"] is True and body["candidate"] is True
    assert body["degraded"] is True
    assert body["error"] == "secret detector failed: RuntimeError"


def test_invisible_characters_do_not_hide_the_candidate(home, dead):
    zw = "​"
    assert _out(run_hook(_call(note=AWS[:6] + zw + AWS[6:]), home=home))[0] == "ask"


# 2. egress, nothing credential-shaped -> the generic {} and a confession
def test_dead_detector_on_benign_egress_defers_and_confesses(home, dead):
    raw = run_hook(_call(note="synthetic benign note 0001"), home=home)
    assert raw == {}
    body = _decision_body(home)
    assert body["rule_id"] == "GLS-FW-ERROR" and body["degraded"] is True
    assert body["secret_lane_down"] is True and body["candidate"] is False


# 3. not an egress tool -> {} even with a key-shaped value
def test_dead_detector_on_non_egress_call_defers(home, dead):
    raw = run_hook(_call("Read", file_path="/tmp/" + AWS), home=home)
    assert raw == {}
    # the detector is never consulted for a call that cannot reach a wire, so it cannot be "down"
    assert "secret_lane_down" not in _decision_body(home)


# 4. the fallback must not fire on prose, placeholders or published canaries
@pytest.mark.parametrize("text", [
    "risk-based review", "task-list item", "ASIA Pacific sales", "sk-learn",
    "a" * 40, "0123456789abcdef0123456789abcdef01234567",
    "sk-" + "x" * 30, "ghp_" + "x" * 36, "AKIA" + "0" * 16,
    "AKIAIOSFODNN7EXAMPLE", "AKIAYVP4CIPPERUVIFXG",
    "the " + "AKIA" + " prefix is documented",
])
def test_fallback_candidate_ignores_non_credentials(text):
    assert firewall._secret_shaped_candidate(text) is False


@pytest.mark.parametrize("text", [AWS, GHP, PEM, "x " + AWS + " y", "k=" + GHP])
def test_fallback_candidate_sees_credentials(text):
    assert firewall._secret_shaped_candidate(text) is True


def test_word_boundary_is_required():
    assert firewall._secret_shaped_candidate("zz" + AWS) is False


# 5. M does not widen: a working detector and a faulty policy lane still deny at the normal point
def test_working_detector_with_dead_policy_still_denies_on_the_secret(home):
    (home / "policy.yaml").write_text("{ not: [valid")
    action, _ = _out(run_hook(_call(note=AWS), home=home))
    assert action == "deny"
    body = _decision_body(home)
    assert body["rule_id"] == "GLS-FW-SEC-AWS" and "secret_lane_down" not in body


# 6. the marker
@pytest.mark.parametrize("word,expected", [
    (None, "ask"), ("ask", "ask"), ("deny", "deny"), ("DENY\n", "deny"),
    ("defer", None), ("block", None), ("banana", "ask"), ("", "ask"),
])
def test_on_error_marker_matrix(home, dead, word, expected):
    if word is not None:
        (home / "on-error").write_text(word)
    raw, reason = run_hook_ex(_call(note=AWS), home=home)
    action = _out(raw)[0]
    assert action == expected
    if word == "block":
        assert raw == {} and reason == "SECRET_LANE_DOWN"
        assert _decision_body(home)["rule_id"] == "GLS-FW-SECRET-DOWN"
    else:
        assert reason is None


@pytest.mark.parametrize("content", [
    "defer" + " " * 59 + "garbage",   # valid word, then padding past the read window, then trailing text
    "defer" + " " * 80,                # oversized
    "defer extra", "de fer", "block\x00x",
])
def test_malformed_marker_never_selects_a_quieter_answer(home, dead, content):
    (home / "on-error").write_text(content)
    assert firewall._read_on_error(home) == "ask"
    assert _out(run_hook(_call(note=AWS), home=home))[0] == "ask"


def test_block_survives_an_unwritable_receipts_path(home, dead, monkeypatch, capsys):
    (home / "on-error").write_text("block")
    (home / "receipts").write_text("a file where the receipts directory belongs")
    raw, reason = run_hook_ex(_call(note=AWS), home=home)
    assert reason == "SECRET_LANE_DOWN"
    monkeypatch.setenv("SUNGLASSES_HOME", str(home))
    monkeypatch.setattr("sys.stdin", io.StringIO(_call(note=AWS)))
    assert firewall.main([]) == 1
    cap = capsys.readouterr()
    assert cap.out == "" and AWS not in cap.err


def test_benign_egress_with_an_unwritable_receipts_path_asks(home, dead):
    (home / "receipts").write_text("a file where the receipts directory belongs")
    raw = run_hook(_call(note="synthetic benign note 0001"), home=home)
    assert _out(raw)[0] == "ask"


@pytest.mark.parametrize("word", ["  DEFER\n", "\tBlock "])
def test_marker_is_read_after_trimming_and_ignoring_case(home, word):
    (home / "on-error").write_text(word)
    assert firewall._read_on_error(home) == word.strip().lower()


@pytest.mark.parametrize("fault", ["load_policy", "load_pins", "check_fuzzy"])
def test_other_lane_faults_with_a_key_present_still_deny_on_the_secret(home, monkeypatch, fault):
    if not hasattr(firewall, fault):
        pytest.skip(fault + " is not a module-level name")
    def _raise(*a, **k):
        raise RuntimeError("lane fault")
    monkeypatch.setattr(firewall, fault, _raise)
    raw = run_hook(_call(note=AWS), home=home)
    assert _out(raw)[0] == "deny"
    assert "secret_lane_down" not in _decision_body(home)


def test_unreadable_marker_means_ask(home, dead):
    (home / "on-error").mkdir()
    assert _out(run_hook(_call(note=AWS), home=home))[0] == "ask"


def test_block_ends_main_as_a_hook_failure(home, dead, monkeypatch, capsys):
    (home / "on-error").write_text("block")
    monkeypatch.setenv("SUNGLASSES_HOME", str(home))
    monkeypatch.setattr("sys.stdin", io.StringIO(_call(note=AWS)))
    assert firewall.main([]) == 1
    cap = capsys.readouterr()
    assert cap.out == ""
    assert "secret detector failed" in cap.err and AWS not in cap.err


def test_scan_failure_falls_back_to_the_generic_defer(home, dead, monkeypatch):
    def _bad(*a, **k):
        raise ValueError("scan broke")
    monkeypatch.setattr(firewall, "egress_surface_text", _bad)
    assert run_hook(_call(note=AWS), home=home) == {}
    assert _decision_body(home)["candidate_scan_failed"] is True


# init --on-error writes the marker (real CLI run in a temp home, never the user's own)
def _init(args, tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path
    home, project = tmp_path / "home", tmp_path / "proj"
    home.mkdir(exist_ok=True)
    project.mkdir(exist_ok=True)
    proc = subprocess.run(
        [sys.executable, "-m", "sunglasses", "init"] + args,
        capture_output=True, text=True, cwd=str(project),
        env={**os.environ, "HOME": str(home), "SUNGLASSES_HOME": str(home / ".sunglasses"),
             "PYTHONPATH": str(Path(__file__).parent.parent)})
    return proc, home / ".sunglasses" / "on-error"


@pytest.mark.parametrize("word", ["ask", "deny", "defer", "block"])
def test_init_on_error_writes_marker(tmp_path, word):
    proc, marker = _init(["--on-error", word], tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert marker.read_text().strip() == word
    assert firewall._read_on_error(marker.parent) == word


def test_init_without_on_error_writes_no_marker(tmp_path):
    proc, marker = _init([], tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert not marker.exists()


def test_init_rejects_an_unknown_on_error_word(tmp_path):
    proc, marker = _init(["--on-error", "banana"], tmp_path)
    assert proc.returncode != 0 and not marker.exists()


# 7. the README says what this does, and leaves the unattended host behaviour as not measured
def test_readme_describes_the_secret_lane_down_answer():
    from pathlib import Path
    text = " ".join((Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8").split())
    assert "the secret check itself raising an exception on an outbound call" in text
    assert "the question says the secret check was down" in text
    assert "nobody can answer the question" not in text
    assert "sunglasses init --on-error {ask,deny,defer,block}" in text
    assert "~/.sunglasses/on-error" in text
    assert "even when the receipt cannot be written" in text
    assert "when the receipt cannot be written the hook asks" in text
    assert "Not measured: what the host does with that question in an unattended run, when its permissions are turned off, or when an allow rule already covers the call." in text


def test_init_help_leaves_the_unattended_host_behaviour_as_not_measured():
    import os
    import subprocess
    import sys
    from pathlib import Path
    proc = subprocess.run([sys.executable, "-m", "sunglasses", "init", "--help"],
                          capture_output=True, text=True,
                          env={**os.environ, "COLUMNS": "400",
                               "PYTHONPATH": str(Path(__file__).parent.parent)})
    text = " ".join(proc.stdout.split())
    assert "nobody can answer an ask" not in text
    assert "Not measured: what the host does with an ask in an unattended run, when its permissions are turned off, or when an allow rule already covers the call" in text
