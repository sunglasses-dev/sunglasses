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
        assert "An empty file is treated as a broken policy, and a tool call that nothing else settles asks until the file is repaired" in flat


# ── what init says and what receipts show ───────────────────────────────────
# The decision table above is unchanged on purpose: nothing here moves a verdict.
# These pin the two places a person reads the state, so "no policy" cannot read
# like "a policy checked this call", on screen as well as on the receipt.

# setup, the word init prints. `active` has no receipt state, init needs a word for it.
INIT_WORDS = [
    ("no policy", _none, "none_configured"),
    ("no policy file but the install marker", _marker_only, "missing"),
    ("empty policy file", _empty, "empty"),
    ("disabled starter", _disabled_starter, "inert"),
    ("a key with no entries", _key_with_no_entries, "inert"),
    ("enabled starter", _enabled_starter, "active"),
    ("active policy that lists something else", _active_but_unrelated, "active"),
]


@pytest.mark.parametrize("name,setup,word", INIT_WORDS, ids=[s[0] for s in INIT_WORDS])
def test_the_init_line_names_the_state_and_the_file(tmp_path, name, setup, word):
    from sunglasses.cli import _policy_state_line
    sh = tmp_path / ".sunglasses"
    sh.mkdir()
    setup(sh)
    line = _policy_state_line(sh)
    assert "\n" not in line, line
    assert f"Policy state {word} for " in line, line
    assert str(sh / "policy.yaml") in line, line


def test_a_dead_policy_control_says_the_firewall_asks(tmp_path):
    from sunglasses.cli import _policy_state_line
    sh = tmp_path / ".sunglasses"
    sh.mkdir()
    _empty(sh)
    assert "asks on any tool call that no other check settles" in _policy_state_line(sh)


def _init(tmp_path, *flags):
    """Run the real `sunglasses init` in a scratch project, the way a person does."""
    home = tmp_path / "home"
    home.mkdir()
    sh = home / ".sunglasses"
    proj = tmp_path / "proj"
    proj.mkdir()
    env = dict(os.environ, HOME=str(home), SUNGLASSES_HOME=str(sh), PYTHONPATH=str(REPO))
    out = subprocess.run([sys.executable, "-m", "sunglasses.cli", "init", *flags],
                         capture_output=True, text=True, env=env, cwd=str(proj),
                         stdin=subprocess.DEVNULL, timeout=180)
    assert out.returncode == 0, out.stdout + out.stderr
    return out.stdout, sh


@pytest.mark.parametrize("flags,word", [
    (("--no-policy",), "none_configured"),
    ((), "inert"),                      # not a terminal: the starter is written commented out
    (("--policy",), "active"),
], ids=["no-policy", "not-a-terminal", "policy"])
def test_init_prints_the_state_line_on_every_road(tmp_path, flags, word):
    """READ THE CALL SITE. The helper is correct and a test of it alone would pass
    with `init` never calling it."""
    stdout, sh = _init(tmp_path, *flags)
    lines = [l for l in stdout.splitlines() if "Policy state" in l]
    assert len(lines) == 1, stdout
    assert f"Policy state {word} for " in lines[0], lines[0]
    assert str(sh / "policy.yaml") in lines[0], lines[0]


def test_init_no_longer_says_deleting_the_policy_enforces_nothing(tmp_path):
    """With the install marker in place a deleted policy asks on every call."""
    stdout, _ = _init(tmp_path, "--policy")
    assert "enforces nothing" not in stdout, stdout
    flat = re.sub(r"\s+", " ", stdout)
    assert "If you delete it, the firewall asks on any tool call that no other check settles, until you restore it" in flat


def test_load_policy_docstring_names_the_marker_not_the_home_directory():
    from sunglasses.firewall import load_policy
    doc = re.sub(r"\s+", " ", load_policy.__doc__)
    assert "no home directory" not in doc, doc
    assert "install marker" in doc, doc


def _receipts(tmp_path, setup):
    _call(tmp_path, setup)
    home = tmp_path / "home"
    env = dict(os.environ, HOME=str(home), SUNGLASSES_HOME=str(home / ".sunglasses"), PYTHONPATH=str(REPO))
    out = subprocess.run([sys.executable, "-m", "sunglasses.cli", "receipts"], capture_output=True,
                         text=True, env=env, cwd=str(home), timeout=120)
    assert out.returncode == 0, out.stdout + out.stderr
    return out.stdout


def test_the_receipt_view_marks_a_call_that_ran_without_a_policy(tmp_path):
    shown = _receipts(tmp_path, _none)
    assert "none_configured" in shown, shown
    assert "ran with no path or host rules loaded" in shown, shown


def test_the_receipt_view_marks_an_inert_policy_the_same_way(tmp_path):
    shown = _receipts(tmp_path, _disabled_starter)
    assert "inert" in shown, shown
    assert "ran with no path or host rules loaded" in shown, shown


def test_the_receipt_view_stays_quiet_for_a_call_a_policy_checked(tmp_path):
    shown = _receipts(tmp_path, _active_but_unrelated)
    assert "none_configured" not in shown and "inert" not in shown, shown
    assert "ran with no path or host rules loaded" not in shown, shown


def test_readme_says_init_and_receipts_name_the_policy_state():
    text = re.sub(r"\s+", " ", (REPO / "README.md").read_text(encoding="utf-8"))
    assert "sunglasses init` prints one line with the state of the policy file and its path" in text
    assert "`sunglasses receipts` marks every call that ran with no policy" in text
