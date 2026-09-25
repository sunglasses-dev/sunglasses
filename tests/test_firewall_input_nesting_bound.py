"""
test_firewall_input_nesting_bound.py — THE HOOK BOUNDS INPUT DEPTH BEFORE IT
PARSES ANYTHING.

The tool input is text the model writes, and every step after arrival walks
all of it: the parse, the surfaces the rules read, the digest in the receipt.
How deep those walks go is therefore set by the caller. Past some depth each of
them raises, and where it raises differs by Python version (the parse on 3.11
and 3.12, the later walks on 3.14). A raise inside the hook is answered as an
internal error, which is not a verdict on the call.

So the bound is taken on the raw text, before either parse in `run_hook`, and
an input past it is denied under its own rule with an ordinary decision
receipt. The depths below cover the point where each supported version starts
raising; the spy test proves the parser never runs on them at all, which is
what makes the version differences irrelevant.
"""
import json
import pathlib
import subprocess
import sys
import time

import pytest

from sunglasses import firewall
from sunglasses.firewall import run_hook, starter_policy_text

BOUND = 64                        # levels, counting the payload object itself
DEEP = (1_000, 10_000, 100_000)   # one past where each version's walk raises
TOKEN = "ghp_" + "R8mK2pX7vQ4nL9sT3wY6zB1cF5hJ0dG8aE2u"   # format-valid, not a canary
KEY_PATH = "~/." + "ssh/id_" + "rsa"

DENIED = {
    "secret-to-mcp": ("mcp__srv__send", "body", TOKEN, "GLS-FW-SEC-GITHUB"),
    "blocked-path-read": ("Read", "file_path", KEY_PATH, "GLS-FW-POL-PATH"),
    "blocked-path-bash": ("Bash", "command", "cat " + KEY_PATH, "GLS-FW-POL-PATH"),
}


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "sunglasses-home"
    h.mkdir()
    (h / "policy.yaml").write_text(starter_policy_text(enabled=True))
    (h / firewall.INSTALL_MARKER).write_text("installed here\n")
    return h


def _raw(tool, key, value, extra_depth):
    """The hook payload as the harness sends it, with one more tool_input key
    holding `extra_depth` nested arrays. Total depth is extra_depth + 2 (the
    payload object and tool_input). Built as text: json.dumps of the nested
    value would itself run out of recursion at these depths."""
    tool_input = json.dumps({key: value})[:-1]
    if extra_depth:
        tool_input += ', "extra": ' + "[" * extra_depth + "]" * extra_depth
    tool_input += "}"
    return ('{"hook_event_name": "PreToolUse", "tool_name": %s, "session_id": "nested", '
            '"tool_input": %s}' % (json.dumps(tool), tool_input))


def _wire(out):
    if out == {}:
        return "{}"
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision")


def _receipts(home):
    d = home / "receipts"
    if not d.exists():
        return []
    return [json.loads(line) for f in sorted(d.glob("*.jsonl"))
            for line in f.read_text().splitlines() if line.strip()]


def _decision(home):
    recs = [r for r in _receipts(home) if r.get("kind") == "decision"]
    assert len(recs) == 1, recs
    return recs[0]


# ── Past the bound: denied under its own rule, in process and in the child ───

@pytest.mark.parametrize("depth", DEEP)
@pytest.mark.parametrize("case", sorted(DENIED))
def test_deep_input_is_denied_under_the_nesting_rule(home, case, depth):
    tool, key, value, _ = DENIED[case]
    out = run_hook(_raw(tool, key, value, depth), home=home)
    assert _wire(out) == "deny", out
    rec = _decision(home)
    assert rec["rule_id"] == "GLS-FW-SEC-NESTING", rec
    assert rec["decision"] == "deny" and rec["lane"] == "deterministic", rec
    assert "error" not in rec and not rec.get("degraded"), rec


@pytest.mark.parametrize("depth", DEEP)
def test_deep_benign_input_is_denied_too(home, depth):
    """Nothing in the call is otherwise denied: the bound alone decides."""
    out = run_hook(_raw("Bash", "command", "ls", depth), home=home)
    assert _wire(out) == "deny", out
    assert _decision(home)["rule_id"] == "GLS-FW-SEC-NESTING"


@pytest.mark.parametrize("depth", DEEP)
def test_deep_input_is_never_parsed(home, monkeypatch, depth):
    """The parser is not called at all, so no version's parse limit and no
    later walk over the parsed value can be reached."""
    calls = []
    real_loads = json.loads

    def spy(*a, **k):
        calls.append(len(a[0]) if a and isinstance(a[0], str) else a)
        raise AssertionError("json.loads ran on the hook payload")

    monkeypatch.setattr(json, "loads", spy)
    out = run_hook(_raw(*DENIED["secret-to-mcp"][:3], depth), home=home)
    monkeypatch.setattr(json, "loads", real_loads)
    assert calls == []
    assert _wire(out) == "deny", out
    assert _decision(home)["rule_id"] == "GLS-FW-SEC-NESTING"


def test_deep_input_still_leaves_a_paired_arrival_record(home):
    run_hook(_raw(*DENIED["blocked-path-read"][:3], DEEP[0]), home=home)
    recs = _receipts(home)
    kinds = [r.get("kind") for r in recs]
    assert kinds == ["in_flight", "decision"], kinds
    assert recs[0]["eval_id"] == recs[1]["eval_id"]


@pytest.mark.parametrize("depth", DEEP)
@pytest.mark.parametrize("case", sorted(DENIED))
def test_deep_input_is_denied_by_the_real_hook_child(tmp_path, case, depth):
    """The same through `python -m sunglasses.firewall`, the process Claude
    Code actually runs, with HOME pointed at a fixture home."""
    base = tmp_path / "user"
    h = base / ".sunglasses"
    h.mkdir(parents=True)
    (h / "policy.yaml").write_text(starter_policy_text(enabled=True))
    (h / firewall.INSTALL_MARKER).write_text("installed here\n")
    tool, key, value, _ = DENIED[case]
    tree = str(pathlib.Path(firewall.__file__).resolve().parents[1])
    env = {"HOME": str(base), "PYTHONPATH": tree, "PYTHONDONTWRITEBYTECODE": "1",
           "PATH": "/usr/bin:/bin"}
    p = subprocess.run([sys.executable, "-m", "sunglasses.firewall"],
                       input=_raw(tool, key, value, depth), capture_output=True,
                       text=True, env=env, timeout=120)
    assert p.returncode == 0, p.stderr[-400:]
    out = json.loads(p.stdout)
    assert _wire(out) == "deny", (p.stdout, p.stderr[-400:])
    assert _decision(h)["rule_id"] == "GLS-FW-SEC-NESTING"


# ── The bound itself ────────────────────────────────────────────────────────

def test_the_bound_is_64_levels():
    assert firewall.MAX_INPUT_NESTING == BOUND


@pytest.mark.parametrize("case", sorted(DENIED))
def test_at_the_bound_the_call_is_evaluated_normally(home, case):
    tool, key, value, rule = DENIED[case]
    run_hook(_raw(tool, key, value, BOUND - 2), home=home)
    assert _decision(home)["rule_id"] == rule


@pytest.mark.parametrize("case", sorted(DENIED))
def test_one_past_the_bound_is_the_nesting_rule(home, case):
    tool, key, value, _ = DENIED[case]
    run_hook(_raw(tool, key, value, BOUND - 1), home=home)
    assert _decision(home)["rule_id"] == "GLS-FW-SEC-NESTING"


def test_objects_count_like_arrays(home):
    tool_input = '{"command": "ls", "extra": ' + '{"a": ' * (BOUND - 1) + "1" + "}" * (BOUND - 1) + "}"
    raw = '{"tool_name": "Bash", "tool_input": %s}' % tool_input
    out = run_hook(raw, home=home)
    assert _wire(out) == "deny"
    assert _decision(home)["rule_id"] == "GLS-FW-SEC-NESTING"


# ── Brackets inside strings are text, not structure ─────────────────────────

BRACKET_TEXT = (
    "[" * 5000,
    "{" * 5000 + "]" * 5000,
    'a \\" ' + "[" * 5000,              # an escaped quote does not end the string
    "\\\\" + "[" * 5000,                # an escaped backslash does not escape the quote
    '"' + "[{" * 5000 + '"',
)


@pytest.mark.parametrize("i", range(len(BRACKET_TEXT)))
def test_brackets_inside_a_string_do_not_count(home, i):
    out = run_hook(json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                               "tool_input": {"command": "echo " + BRACKET_TEXT[i]}}),
                   home=home)
    assert out == {}, out
    assert _decision(home)["rule_id"] == "GLS-FW-CLEAN"


def test_a_denied_value_full_of_brackets_keeps_its_own_rule(home):
    run_hook(json.dumps({"hook_event_name": "PreToolUse", "tool_name": "mcp__srv__send",
                         "tool_input": {"body": TOKEN + " " + "[" * 5000}}), home=home)
    assert _decision(home)["rule_id"] == "GLS-FW-SEC-GITHUB"


@pytest.mark.parametrize("text, deep", [
    ("", False),
    ("{}", False),
    ("[" * BOUND, False),
    ("[" * (BOUND + 1), True),
    ("[" * BOUND + "]" + "[", False),
    ('"' + "[" * 500, False),                     # string left open to the end
    ('"' + "[" * 500 + "\\", False),              # ... ending on a lone backslash
    ('["\\"' + "[" * 500 + '"]', False),
    ('["\\\\"' + ", " + "[" * (BOUND + 1), True),  # the quote after \\ closes
    ("]" * 500 + "[" * BOUND, False),
])
def test_input_too_deep_on_raw_text(text, deep):
    assert firewall.input_too_deep(text) is deep


def test_the_scan_is_linear_on_hostile_text():
    """Strings that never close and escapes that never end cost one pass,
    not one pass per quote."""
    samples = (
        '"' + '\\"' * 1_000_000,
        '"' + "\\" * 2_000_001,
        '["' * 700_000,
        "[]" * 1_000_000,
    )
    for text in samples:
        started = time.perf_counter()
        firewall.input_too_deep(text)
        assert time.perf_counter() - started < 2.0, text[:20]


# ── Controls: the shallow answers are what they were ────────────────────────

@pytest.mark.parametrize("depth", (0, 50))
@pytest.mark.parametrize("case", sorted(DENIED))
def test_shallow_denials_keep_their_rule(home, case, depth):
    tool, key, value, rule = DENIED[case]
    out = run_hook(_raw(tool, key, value, depth), home=home)
    assert _wire(out) == "deny", out
    assert _decision(home)["rule_id"] == rule


def test_a_shallow_benign_call_stays_clean(home):
    out = run_hook(_raw("Bash", "command", "ls", 50), home=home)
    assert out == {}, out
    assert _decision(home)["rule_id"] == "GLS-FW-CLEAN"
