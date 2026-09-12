"""
test_firewall_failure_states.py — A DEAD CONTROL MUST SAY SO (RED 4).

Every state below used to end the same way: the policy lane produced no opinion,
the hook emitted `{}`, and the call fell through to the normal permission flow
with nothing on screen to say the control was down.

`{}` is indistinguishable from "I looked and this is fine". That is the defect.
A firewall that is quietly off looks exactly like one that checked and found
nothing, and the user has no way to tell which they are living with.

Each state now ASKS, and the question names which control died. Asking is
deliberately annoying; the fix is to repair the policy, not to learn to click
through. Each fixture below is paired with a MUTATION that restores the old
fall-through, so none of these can quietly regress to `{}`.

F1 policy missing · F2 corrupt · F3 unreadable · F4 empty · F5 not a mapping
F6 the audit trail cannot be written
"""
import json
import os
import pathlib
import tempfile

import pytest

from sunglasses import firewall
from sunglasses.firewall import PolicyDown, run_hook, starter_policy_text

CLEAN = json.dumps({
    "hook_event_name": "PreToolUse", "tool_name": "Bash",
    "tool_input": {"command": "echo hello"}, "session_id": "failure-states",
})
# Built rather than written literally: a Bash command whose TEXT names a blocked
# path is denied by our own firewall, which is a documented limit of this repo.
SECRET_PATH = "~/." + "ssh/id_" + "rsa"
DENIED = json.dumps({
    "hook_event_name": "PreToolUse", "tool_name": "Read",
    "tool_input": {"file_path": SECRET_PATH}, "session_id": "failure-states",
})


def _decision(home, payload=CLEAN):
    out = run_hook(payload, home=home).get("hookSpecificOutput", {})
    return out.get("permissionDecision"), out.get("permissionDecisionReason", "")


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "sunglasses-home"
    h.mkdir()
    return h


def _healthy(home):
    (home / "policy.yaml").write_text(starter_policy_text(enabled=True))
    return home


# ── F1..F5: the policy file ──────────────────────────────────────────────────

STATES = [
    ("F1_missing",    None,                    "gone"),
    ("F2_corrupt",    "blocked_paths: [\n",    "does not parse"),
    ("F3_unreadable", "__CHMOD__",             "cannot be read"),
    ("F4_empty",      "   \n\n",               "is empty"),
]


@pytest.mark.parametrize("label,content,phrase", STATES, ids=[s[0] for s in STATES])
def test_a_dead_policy_asks_and_names_the_control(home, label, content, phrase):
    path = home / "policy.yaml"
    # A missing policy is only a DEAD control where one was installed. The marker
    # is what says so; without it a machine that never ran `init` would be asked
    # on every call forever, which is the cry-wolf failure this must not become.
    (home / firewall.INSTALL_MARKER).write_text("installed here\n")
    if content == "__CHMOD__":
        path.write_text(starter_policy_text(enabled=True))
        os.chmod(path, 0o000)
    elif content is not None:
        path.write_text(content)
    try:
        action, reason = _decision(home)
    finally:
        if content == "__CHMOD__":
            os.chmod(path, 0o600)
    assert action == "ask", f"{label}: a dead control must ask, got {action!r}"
    assert phrase in reason, f"{label}: the reason must name the state, got {reason!r}"
    assert "policy" in reason.lower(), f"{label}: the reason must name the control"


def test_a_machine_that_never_installed_a_policy_is_not_nagged(home):
    """No marker, no policy, no noise.

    `write_receipt` creates the home directory itself on the first call, so
    "the directory exists" is not evidence a policy was ever configured. The
    first draft of this feature used exactly that signal and would have asked
    on every call on a fresh machine.
    """
    action, _ = _decision(home)
    assert action is None, (
        f"an unconfigured machine must stay silent, got {action!r}"
    )


def test_a_healthy_policy_is_unchanged(home):
    """The whole value of asking depends on not asking the rest of the time."""
    action, _ = _decision(_healthy(home))
    assert action is None, (
        f"a working policy must still fall through silently, got {action!r}; "
        "a firewall that asks on every ordinary call gets clicked through"
    )


def test_f5_a_policy_that_is_not_a_mapping_is_rejected():
    """Defence in depth, and honest about it.

    The shipped parser raises on a list document, so this state is not reachable
    through `load_policy` today. The check exists so that a future parser change
    cannot turn a non-mapping policy into an attribute error at hook time.
    """
    original = firewall.parse_policy
    firewall.parse_policy = lambda _text: ["not", "a", "mapping"]
    try:
        home = pathlib.Path(tempfile.mkdtemp()) / "home"
        home.mkdir()
        (home / "policy.yaml").write_text("anything\n")
        with pytest.raises(PolicyDown) as caught:
            firewall.load_policy(home / "policy.yaml")
        assert caught.value.state == "wrong_type"
    finally:
        firewall.parse_policy = original


# ── F6: the audit trail ──────────────────────────────────────────────────────

def _break_receipts(home):
    """A plain file where the receipts directory belongs.

    Not a chmod: `write_receipt` repairs a loose directory mode by design, so a
    mode-only failure self-heals and is not an unwritable state at all.
    """
    (home / "receipts").write_text("not a directory\n")


def test_f6_an_unrecordable_call_asks(home):
    _healthy(home)
    _break_receipts(home)
    action, reason = _decision(home)
    assert action == "ask"
    assert "audit trail" in reason, reason


def test_f6_a_block_stays_a_block_when_the_audit_trail_is_down(home):
    """Losing an audit line must not WEAKEN a decision.

    Upgrading a deny to an ask because the disk is full would turn a storage
    problem into a security downgrade.
    """
    _healthy(home)
    _break_receipts(home)
    action, _ = _decision(home, DENIED)
    assert action == "deny", f"a block must survive an unwritable audit trail, got {action!r}"


# ── MUTATIONS: each one restores the silent fall-through ─────────────────────

@pytest.mark.parametrize("label,content", [(s[0], s[1]) for s in STATES],
                         ids=[s[0] for s in STATES])
def test_control_the_old_fall_through_returns_empty_for_every_state(home, label, content):
    """The world before this change, one state at a time.

    `load_policy` used to answer `{}` for an absent file and raise a generic
    error for the rest, both of which ended as `{}` on the wire. With that
    behaviour restored every state below goes silent again, which is what makes
    the assertions above worth anything.
    """
    path = home / "policy.yaml"
    if content == "__CHMOD__":
        path.write_text(starter_policy_text(enabled=True))
        os.chmod(path, 0o000)
    elif content is not None:
        path.write_text(content)

    original = firewall.load_policy
    firewall.load_policy = lambda _p: {}          # the old silent answer
    try:
        action, _ = _decision(home)
    finally:
        firewall.load_policy = original
        if content == "__CHMOD__":
            os.chmod(path, 0o600)
    assert action is None, (
        f"{label}: with the old behaviour restored this must fall through silently; "
        "if it does not, these tests are not measuring the change they claim to"
    )


def test_control_the_old_receipt_handling_swallows_an_unwritable_trail(home):
    _healthy(home)
    _break_receipts(home)
    original = firewall.write_receipt
    firewall.write_receipt = lambda *a, **k: None   # the old "pass" on failure
    try:
        action, _ = _decision(home)
    finally:
        firewall.write_receipt = original
    assert action is None, (
        "with the failure swallowed the call goes silent again, which is the "
        "behaviour F6 replaces"
    )
