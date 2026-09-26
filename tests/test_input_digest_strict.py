"""Finding #8: the receipt's input digest never hashes a SUBSTITUTED byte.

`_input_digest` encoded the canonical tool input with `errors="replace"`, so
every lone surrogate became `?` before hashing. `{"cmd": "x\\ud800"}`,
`{"cmd": "x\\ud801"}` and `{"cmd": "x?"}` -- three different inputs -- got one
digest, and a receipt that names an input by its digest named the wrong one.

The repair (T9 ruling, 2026-09-23): encode strictly. An input that cannot be
encoded gets `input_sha256: null` and `input_sha256_reason: "unencodable"`;
an encodable input is hashed exactly as before, byte for byte.

Every row runs the three inputs together: the two surrogates are the defect,
`x?` is the paired control, the byte-identical legacy digest.
"""
import hashlib
import json

import pytest

from sunglasses import firewall

SURROGATES = {"x\ud800": "lone high surrogate", "x\ud801": "a second one"}
CONTROL = "x?"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SUNGLASSES_HOME", str(tmp_path))
    return tmp_path


def _receipts(home):
    files = sorted((home / "receipts").glob("*.jsonl"))
    return [json.loads(line) for f in files
            for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]


def _hook(home, cmd):
    """One arrival through the hook's own entry point. `json.dumps` writes the
    surrogate as a `\\ud800` escape, which is how it arrives on stdin."""
    payload = {"session_id": "s1", "hook_event_name": "PreToolUse", "cwd": "/tmp",
               "tool_name": "Bash", "tool_input": {"cmd": cmd}, "tool_use_id": "t1"}
    before = len(_receipts(home)) if (home / "receipts").exists() else 0
    firewall.run_hook(json.dumps(payload))
    rows = _receipts(home)[before:]
    assert [r["kind"] for r in rows] == ["in_flight", "decision"]
    return rows


def _legacy(cmd):
    """The digest main computed for an ENCODABLE input: kept byte-identical."""
    canonical = json.dumps({"cmd": cmd}, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("cmd", sorted(SURROGATES))
def test_unencodable_input_gets_no_digest_and_says_why(home, cmd):
    for row in _hook(home, cmd):
        assert row["input_sha256"] is None, (
            f"{row['kind']}: {cmd!r} was hashed after a byte was substituted")
        assert row["input_sha256_reason"] == "unencodable"


def test_control_encodable_input_keeps_the_legacy_digest(home):
    for row in _hook(home, CONTROL):
        assert row["input_sha256"] == _legacy(CONTROL)
        assert "input_sha256_reason" not in row


def test_the_three_inputs_never_share_a_digest(home):
    """The collision itself, stated as the property: no two of the three
    inputs are named by the same digest string."""
    digests = [row["input_sha256"] for cmd in (*sorted(SURROGATES), CONTROL)
               for row in _hook(home, cmd)[-1:]]
    named = [d for d in digests if d is not None]
    assert len(named) == len(set(named)) == 1, digests
    assert digests[-1] == _legacy(CONTROL)


def test_unit_digest_is_none_only_for_the_unencodable(home):
    for cmd in SURROGATES:
        assert firewall._input_digest({"cmd": cmd}) is None
    assert firewall._input_digest({"cmd": CONTROL}) == _legacy(CONTROL)
    assert firewall._input_digest(None) == hashlib.sha256(b"null").hexdigest()
