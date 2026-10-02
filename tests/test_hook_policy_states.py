"""What the Claude Code hook does, and what its receipt says, for each state a policy can be in.

Row 13 of the 0.6.5 follow ups. Measured on 89cd6e0e, a Read of a key shaped path:
no policy and a disabled starter policy both DEFER, and both wrote the same receipt (GLS-FW-CLEAN) as a policy that
was read and found nothing. The decision was right, the record was not: an auditor could not tell "no policy" from
"policy checked this call and it was fine".

This file pins two things together so neither can move alone.
  1. The decision for every state. With no policy the hook has no opinion about a credential path, which is the
     fail open default. Whoever flips that default has to change this table and the README sentence in one commit.
  2. The receipt names the state: none_configured when there is no policy file, inert when the file has no enabled
     entry. A policy that was read and listed something else carries no state at all.
The key path is assembled at run time so no literal credential path sits in this file.
"""
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
SSH = "." + "ssh"
KEY = "id_" + "ed25519"
OLD_HEADER = "an empty file (or no file at all) enforces nothing"


def _none(sh):
    pass


def _marker_only(sh):
    (sh / "installed").write_text("x\n", encoding="utf-8")


def _empty(sh):
    (sh / "policy.yaml").write_text("", encoding="utf-8")


def _disabled_starter(sh):
    from sunglasses.firewall import write_starter_policy
    write_starter_policy(home=sh, enabled=False)


def _enabled_starter(sh):
    from sunglasses.firewall import write_starter_policy
    write_starter_policy(home=sh, enabled=True)


def _key_with_no_entries(sh):
    (sh / "policy.yaml").write_text("blocked_paths:\n", encoding="utf-8")


def _active_but_unrelated(sh):
    (sh / "policy.yaml").write_text("blocked_paths:\n  - /opt/not-a-credential-dir\n", encoding="utf-8")


def _call(tmp_path, setup):
    home = tmp_path / "home"
    (home / SSH).mkdir(parents=True)
    key = home / SSH / KEY
    key.write_text("scratch file, not a key\n", encoding="utf-8")
    sh = home / ".sunglasses"
    sh.mkdir()
    setup(sh)
    env = dict(os.environ, HOME=str(home), SUNGLASSES_HOME=str(sh), PYTHONPATH=str(REPO))
    event = {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": str(key)}, "cwd": str(home)}
    out = subprocess.run([sys.executable, "-m", "sunglasses.cli", "firewall-hook"], input=json.dumps(event),
                         capture_output=True, text=True, env=env, cwd=str(home), timeout=120)
    assert out.returncode == 0, out.stderr
    text = out.stdout.strip()
    decision = "defer" if (not text or text == "{}") else json.loads(text)["hookSpecificOutput"]["permissionDecision"]
    records = []
    for f in sorted(sh.rglob("*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("kind") == "decision":
                records.append(rec)
    assert len(records) == 1, records
    return decision, records[0]


# state, setup, decision, rule id, policy_state on the receipt (None = the field is absent)
STATES = [
    ("no policy", _none, "defer", "GLS-FW-CLEAN", "none_configured"),
    ("no policy file but the install marker", _marker_only, "ask", "GLS-FW-POLICY-MISSING", "missing"),
    ("empty policy file", _empty, "ask", "GLS-FW-POLICY-EMPTY", "empty"),
    ("disabled starter", _disabled_starter, "defer", "GLS-FW-CLEAN", "inert"),
    ("a key with no entries", _key_with_no_entries, "defer", "GLS-FW-CLEAN", "inert"),
    ("enabled starter", _enabled_starter, "deny", "GLS-FW-POL-PATH", None),
    ("active policy that lists something else", _active_but_unrelated, "defer", "GLS-FW-CLEAN", None),
]
IDS = [s[0] for s in STATES]


@pytest.mark.parametrize("name,setup,decision,rule_id,state", STATES, ids=IDS)
def test_the_decision_for_each_policy_state(tmp_path, name, setup, decision, rule_id, state):
    got, rec = _call(tmp_path, setup)
    assert got == decision, (name, got)
    assert rec["decision"] == decision and rec["rule_id"] == rule_id, rec


@pytest.mark.parametrize("name,setup,decision,rule_id,state", STATES, ids=IDS)
def test_the_receipt_names_the_policy_state(tmp_path, name, setup, decision, rule_id, state):
    _, rec = _call(tmp_path, setup)
    assert rec.get("policy_state") == state, (name, rec)


def test_no_policy_does_not_read_like_a_policy_that_found_nothing(tmp_path):
    _, none_rec = _call(tmp_path / "a", _none)
    _, read_rec = _call(tmp_path / "b", _active_but_unrelated)
    assert none_rec["rule_id"] == read_rec["rule_id"] == "GLS-FW-CLEAN"
    assert none_rec.get("policy_state") != read_rec.get("policy_state")


def _readme_lines():
    return (REPO / "README.md").read_text(encoding="utf-8").splitlines()


def test_readme_hook_bullet_says_your_policy_lists():
    bullet = next(l for l in _readme_lines() if l.startswith("- A Claude Code hook that blocks"))
    assert "your policy lists" in bullet, bullet


def test_readme_opening_line_does_not_promise_credential_leaks_it_cannot_see():
    """A key piped to curl carries no secret in the command text. Blocking it is the policy's job."""
    opening = next(l for l in _readme_lines() if l.startswith("**Open source input firewall"))
    assert "credential leaks" not in opening, opening
    assert "secret material" in opening and "your policy lists" in opening, opening


def test_readme_still_says_a_fresh_install_blocks_nothing_it_was_not_asked_to():
    text = re.sub(r"\s+", " ", (REPO / "README.md").read_text(encoding="utf-8"))
    assert "a fresh install still blocks nothing you did not ask it to" in text


def test_the_policy_file_header_does_not_say_an_empty_file_enforces_nothing(tmp_path):
    """An empty policy file asks on every call, so the file must not say it is harmless."""
    from sunglasses.firewall import starter_policy_text
    for enabled in (True, False):
        text = starter_policy_text(enabled=enabled)
        flat = re.sub(r"\s*\n#\s*", " ", text)  # comment wrapping must not hide the sentence
        assert OLD_HEADER not in flat
        assert "An empty file is treated as a broken policy and asks before each tool call" in flat
