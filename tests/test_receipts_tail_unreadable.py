"""T9 RULINGS 34 and 35. A receipts failure the hook did not catch was an OPEN
door, not a closed one.

ASTRA receipts-3e8d648 r2. `_HookReceipts(home)` was built above the hook's
guard, and deciding whether the user opted in reads the hook chain's last
segment with a bare `open()`. With the key deleted, no `receipts off`, and that
segment unreadable, the PermissionError escaped `run_hook`, the hook process
exited 1 with nothing on stdout, and the host -- which blocks only on exit 2 and
reads a decision only on exit 0 -- let the call proceed, unchecked.

Every row runs the REAL entry point, `python -m sunglasses.firewall`, because
the property is the host contract: a decision on stdout and exit 0. Exit 1 is
the fail-open, and no row here may ever see it.
"""
import io
import json
import os
import pathlib
import subprocess
import sys

import pytest

from sunglasses import firewall
from sunglasses.firewall import run_hook
from sunglasses.receipts import chain, keys, optin

TREE = pathlib.Path(__file__).resolve().parents[1]
CALL = json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "echo hello"},
    "session_id": "r34-test",
})


@pytest.fixture
def home(tmp_path):
    """A home that opted in: a key, and one sealed hook call on its chain."""
    home = tmp_path / "sunglasses-home"
    keys.init(home)
    run_hook(CALL, home=home)
    return home


def _tail(home):
    return sorted((home / "receipts" / "hook").glob(chain.SEGMENT_GLOB))[-1]


def _legacy(home):
    return sorted((home / "receipts").glob("*.jsonl"))


@pytest.fixture
def unreadable_tail(home):
    tail = _tail(home)
    os.chmod(tail, 0)
    yield tail
    os.chmod(tail, 0o600)


def _hook(home):
    """The hook as the host runs it. Exit 1 is the fail-open this file exists
    for, so every row asserts exit 0 before it reads anything."""
    env = {**os.environ, "SUNGLASSES_HOME": str(home)}
    proc = subprocess.run([sys.executable, "-m", "sunglasses.firewall"],
                          input=CALL, cwd=TREE, env=env,
                          capture_output=True, text=True)
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-400:])
    return json.loads(proc.stdout)


def _decision(out):
    spec = out.get("hookSpecificOutput", {})
    return spec.get("permissionDecision"), spec.get("permissionDecisionReason", "")


# ── (a) the ASTRA sequence ───────────────────────────────────────────────────

def test_a_deleted_key_under_an_unreadable_tail_asks_and_names_the_cause(
        home, unreadable_tail):
    keys.private_path(home).unlink()
    kind, reason = _decision(_hook(home))
    assert kind == "ask", reason
    assert "KEY_UNUSABLE" in reason, reason
    assert _legacy(home) == [], "a signed log never turns unsigned by itself"


def test_an_unreadable_tail_is_opted_in_not_an_error(home, unreadable_tail):
    """Layer 1. The comment at the read said this all along; the code let the
    OSError out. A tail nobody can read is not an off record."""
    keys.private_path(home).unlink()
    assert optin.opted_in(home) is True


def test_a_receipts_constructor_that_raises_still_asks(home, monkeypatch):
    """Layer 2. Whatever the receipts path raises, and wherever, the hook
    answers: an otherwise permissive call asks, naming the cause."""
    def broken(_home):
        raise OSError("injected: the receipts directory cannot be read")
    monkeypatch.setattr(firewall, "_HookReceipts", broken)
    kind, reason = _decision(run_hook(CALL, home=home))
    assert kind == "ask", reason
    assert "RECEIPT_IO_ERROR" in reason, reason


def test_an_opening_that_raises_asks_rather_than_proceeding(home, monkeypatch):
    """Layer 2, the opening record. Losing it used to be swallowed, so a call
    with no opening record proceeded; it is a receipts failure like any other."""
    def broken(self, row):
        raise OSError("injected full disk at the opening")
    monkeypatch.setattr(firewall._HookReceipts, "opening", broken)
    kind, reason = _decision(run_hook(CALL, home=home))
    assert kind == "ask", reason
    assert "RECEIPT_IO_ERROR" in reason, reason


class _Unprintable(Exception):
    def __str__(self):
        raise RuntimeError("the exception cannot even describe itself")


def test_the_entry_point_answers_even_when_run_hook_raises(monkeypatch, capsys):
    """The belt. Nothing that escapes `run_hook` may reach the interpreter's
    exit 1, including an exception whose own text raises: the answer names
    the exception's TYPE and nothing it says about itself."""
    def raising(stdin_text, home=None):
        raise _Unprintable()
    monkeypatch.setattr(firewall, "run_hook", raising)
    monkeypatch.setattr(sys, "stdin", io.StringIO(CALL))
    assert firewall.main([]) == 0
    kind, reason = _decision(json.loads(capsys.readouterr().out))
    assert kind == "ask", reason
    assert "_Unprintable" in reason, reason


# ── (b) no over-close: what did not fail keeps its answer ────────────────────

def test_the_control_a_usable_key_and_a_readable_tail_defer(home):
    assert _hook(home) == {}
    assert _legacy(home) == []


def test_the_control_a_usable_key_and_an_unreadable_tail_asks_as_before(
        home, unreadable_tail):
    """Unchanged by this fix: the chain cannot be continued from a tail it
    cannot read, so the call has no record and asks. No unsigned fallback."""
    kind, _ = _decision(_hook(home))
    assert kind == "ask"
    assert _legacy(home) == []


def test_the_control_off_is_still_off(home):
    """`receipts off` last, key retired: not opted in, so the hook defers and
    writes the legacy day file. The OSError catch must not reopen a chain the
    user closed."""
    optin.turn_off(home)
    assert optin.opted_in(home) is False
    assert _hook(home) == {}
    assert _legacy(home) != []


def test_the_control_a_home_that_never_opted_in_defers(tmp_path):
    home = tmp_path / "never"
    assert _hook(home) == {}
    assert _legacy(home) != []
