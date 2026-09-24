"""
test_receipts_hook_chain.py — the hook writes its signed log once the user has
a key (#172).

T9 RULING 11 Q1: the chain IS the log when enabled; with no key the legacy path
is unchanged, and it does not even import the signing code. Q3: a chained row
carries the error's class name, never its message; the legacy row keeps its
message. RULING 15: each call seals its own rows; a call that dies leaves its
opening unsigned, and the next call opens a new segment naming the last
checkpoint that verifies.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

from sunglasses import firewall
from sunglasses.firewall import run_hook
from sunglasses.receipts import keys, verify, wire

TREE = pathlib.Path(__file__).resolve().parents[1]
PAYLOAD = json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "echo hello"},
    "session_id": "chain-test",
})
SECRET_TEXT = "the-value-that-raised-xyzzy"


@pytest.fixture
def home(tmp_path):
    return tmp_path / "sunglasses-home"


@pytest.fixture
def keyed(home):
    keys.init(home)
    return home


def _log(home):
    return home / "receipts" / "hook"


def _report(home):
    signer = keys.load(home)
    public = keys.public_path(home, signer.fingerprint).read_bytes()
    return verify.verify_log(_log(home), public, expected_fingerprint=signer.fingerprint)


def _bodies(home):
    out = []
    for segment in sorted(_log(home).glob("segment-*.chain")):
        for line in segment.read_bytes().splitlines(keepends=True):
            record = wire.decode_strict(line)
            if record["event"] in ("in_flight", "decision"):
                out.append((record["event"], record["body"]))
    return out


# ── no key: nothing changes ──────────────────────────────────────────────────

def test_without_a_key_the_hook_never_loads_the_signing_code(home):
    script = (
        "import sys, pathlib\n"
        "from sunglasses.firewall import run_hook\n"
        f"run_hook({PAYLOAD!r}, home=pathlib.Path({str(home)!r}))\n"
        "print(sorted(m for m in sys.modules\n"
        "             if m.startswith(('sunglasses.receipts', 'cryptography'))))\n")
    proc = subprocess.run([sys.executable, "-c", script], cwd=TREE,
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "[]"
    assert len(list((home / "receipts").glob("*.jsonl"))) == 1
    assert not _log(home).exists()
    assert not (home / "keys").exists()


def test_without_a_key_the_legacy_row_keeps_its_error_message(home, monkeypatch):
    def boom(payload, home=None):
        raise ValueError(SECRET_TEXT)
    monkeypatch.setattr(firewall, "evaluate", boom)
    run_hook(PAYLOAD, home=home)
    text = "".join(p.read_text() for p in (home / "receipts").glob("*.jsonl"))
    assert f"ValueError: {SECRET_TEXT}" in text


# ── a key: the chain is the log ──────────────────────────────────────────────

def test_with_a_key_each_call_is_sealed_and_no_legacy_line_is_written(keyed):
    run_hook(PAYLOAD, home=keyed)
    run_hook(PAYLOAD, home=keyed)
    assert list((keyed / "receipts").glob("*.jsonl")) == []
    report = _report(keyed)
    assert report.results["chain_integrity"] == "CHAIN_OK"
    assert report.results["unsigned_tail"] == "NO_VISIBLE_TAIL"
    assert report.results["lifecycle"] == "LIFECYCLE_COMPLETE"
    kinds = [kind for kind, _ in _bodies(keyed)]
    assert kinds == ["in_flight", "decision", "in_flight", "decision"]


def test_the_chained_pair_shares_an_eval_id_and_carries_the_decision(keyed):
    run_hook(PAYLOAD, home=keyed)
    (_, opening), (_, terminal) = _bodies(keyed)
    assert opening["eval_id"] == terminal["eval_id"]
    assert opening["tool_name"] == "Bash"
    assert terminal["decision"] == "defer"
    assert terminal["rule_id"] == "GLS-FW-CLEAN"
    assert isinstance(terminal["elapsed_us"], int)


def test_a_chained_error_carries_its_class_name_never_its_message(keyed, monkeypatch):
    def boom(payload, home=None):
        raise ValueError(SECRET_TEXT)
    monkeypatch.setattr(firewall, "evaluate", boom)
    run_hook(PAYLOAD, home=keyed)
    raw = b"".join(p.read_bytes() for p in _log(keyed).glob("segment-*.chain"))
    assert SECRET_TEXT.encode() not in raw
    _, terminal = _bodies(keyed)[-1]
    assert terminal["error_types"] == ["ValueError"]
    assert terminal["degraded"] is True


def test_a_dead_policy_control_is_named_by_class_in_the_chain(keyed):
    (keyed / "policy.yaml").write_text(f"{SECRET_TEXT}: [unclosed\n")
    run_hook(PAYLOAD, home=keyed)
    raw = b"".join(p.read_bytes() for p in _log(keyed).glob("segment-*.chain"))
    assert SECRET_TEXT.encode() not in raw
    _, terminal = _bodies(keyed)[-1]
    assert terminal.get("error_types"), terminal
    assert all(name.isidentifier() for name in terminal["error_types"])


def test_a_call_that_died_leaves_its_opening_unsigned_and_the_next_call_moves_on(
        keyed, monkeypatch):
    def killed(payload, home=None):
        raise SystemExit("killed mid-evaluation")      # not caught: the process ends
    with monkeypatch.context() as m:
        m.setattr(firewall, "evaluate", killed)
        with pytest.raises(SystemExit):
            run_hook(PAYLOAD, home=keyed)
    run_hook(PAYLOAD, home=keyed)
    report = _report(keyed)
    assert report.results["chain_integrity"] == "CHAIN_OK"
    assert report.results["unsigned_tail"] == "UNVERIFIED_TAIL"
    assert len(report.segments) == 2
    tails = [s.results["unsigned_tail"] for _, s in report.segments]
    assert tails == ["UNVERIFIED_TAIL", "NO_VISIBLE_TAIL"]


# ── a key the hook cannot use: the audit trail is down, said out loud ────────

def test_an_unusable_key_asks_instead_of_writing_unsigned(keyed):
    os.chmod(keys.private_path(keyed), 0o644)           # load() refuses it
    out = run_hook(PAYLOAD, home=keyed)["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask"
    assert "audit trail" in out["permissionDecisionReason"]
    assert list((keyed / "receipts").glob("*.jsonl")) == []


def test_an_unusable_key_never_softens_a_deny(keyed):
    from sunglasses.firewall import starter_policy_text
    (keyed / "policy.yaml").write_text(starter_policy_text(enabled=True))
    secret = "~/" + ".ss" + "h/id" + "_rsa"         # kept out of this file's own text
    denied = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Read",
                         "tool_input": {"file_path": secret},
                         "session_id": "chain-test"})
    control = run_hook(denied, home=keyed)              # the key is usable here
    assert control["hookSpecificOutput"]["permissionDecision"] == "deny", control
    os.chmod(keys.private_path(keyed), 0o644)
    out = run_hook(denied, home=keyed)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny", out


def test_a_key_with_the_extra_gone_asks_and_writes_no_unsigned_line(keyed, tmp_path):
    fake = tmp_path / "no-crypto" / "cryptography"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text("raise ImportError('not installed (test)')\n")
    script = (
        "import json, pathlib\n"
        "from sunglasses.firewall import run_hook\n"
        f"print(json.dumps(run_hook({PAYLOAD!r}, home=pathlib.Path({str(keyed)!r}))))\n")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(fake.parent), str(TREE)]))
    proc = subprocess.run([sys.executable, "-c", script], cwd=TREE,
                          capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask"
    assert "audit trail" in out["permissionDecisionReason"]
    assert list((keyed / "receipts").glob("*.jsonl")) == []
