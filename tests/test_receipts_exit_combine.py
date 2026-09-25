"""
test_receipts_exit_combine.py — one combiner for every verdict `receipts
--verify` prints (T9 ruling 50, C5).

At 5480cdd the key verdict was assigned, then overwritten by the legacy
lifecycle verdict: a key that cannot sign plus a clean legacy day exited 0.
With a hook chain as well, the chain's limit (3) then stood in for the key's
failure (1). One rule now joins the key, the legacy log and the chains: any
failure wins, then a usage error, then any limit. A numeric max() is not that
rule, since max(1, 3) = 3 would hide the failure.
"""
import json
import os
import re
import subprocess
import sys
import pathlib

import pytest

pytest.importorskip("cryptography")

from sunglasses.receipts import chain, codes, keys  # noqa: E402

TREE = pathlib.Path(__file__).resolve().parents[1]


def _cli(home, *argv):
    env = dict(os.environ, SUNGLASSES_HOME=str(home))
    proc = subprocess.run([sys.executable, "-m", "sunglasses.cli", "receipts", *argv],
                          cwd=TREE, capture_output=True, text=True, env=env)
    return proc.returncode, re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout + proc.stderr)


def _legacy(home):
    """A clean legacy day: one call, opening and terminal paired."""
    d = home / "receipts"
    d.mkdir(parents=True, exist_ok=True)
    rows = [{"kind": "in_flight", "eval_id": "e1", "ts": "2026-09-24T01:00:00",
             "tool_name": "Bash"},
            {"kind": "decision", "eval_id": "e1", "ts": "2026-09-24T01:00:00",
             "tool_name": "Bash", "decision": "allow"}]
    (d / "2026-09-24.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))


def _break_key(home):
    """A key that is there and cannot sign: 0644 is refused by name."""
    os.chmod(keys.private_path(home), 0o644)


@pytest.fixture
def home(tmp_path):
    home = tmp_path / "sunglasses-home"
    keys.init(home)
    return home


def _hook_chain(home):
    chain.Chain(home / "receipts" / "hook", keys.load(home), producer="hook").write(
        [{"event": "in_flight", "body": {"eval_id": "e1"}},
         {"event": "decision", "body": {"eval_id": "e1"}}], seal="close")


def test_a_broken_key_is_not_cleared_by_a_clean_legacy_day(home):
    _legacy(home)
    _break_key(home)
    code, out = _cli(home, "--verify")
    assert "KEY_UNUSABLE" in out, out
    assert "LEGACY_UNSIGNED" in out, out
    assert code == codes.EXIT_FAIL, out


def test_the_control_a_clean_legacy_day_with_a_usable_key_exits_0(home):
    _legacy(home)
    code, out = _cli(home, "--verify")
    assert "KEY_UNUSABLE" not in out, out
    assert code == 0, out


def test_a_broken_key_with_a_legacy_day_and_a_chain_limit_is_1_never_3(home):
    _hook_chain(home)
    _legacy(home)
    _break_key(home)
    code, out = _cli(home, "--verify")
    assert "KEY_UNUSABLE" in out, out
    assert "key_trust: KEY_UNTRUSTED" in out, out      # the chain's limit is there
    assert code == codes.EXIT_FAIL, out


def test_the_control_the_same_chain_alone_is_a_limit(home):
    _hook_chain(home)
    code, out = _cli(home, "--verify")
    assert "KEY_UNUSABLE" not in out, out
    assert code == codes.EXIT_LIMIT, out


@pytest.mark.parametrize("exits,combined", [
    ((), 0), ((0,), 0), ((0, 0), 0), ((3,), 3), ((0, 3), 3), ((3, 0), 3), ((3, 3), 3),
    ((1, 3), 1), ((3, 1), 1), ((1, 0, 3), 1), ((2, 3), 2), ((3, 2), 2),
    ((1, 2), 1), ((2, 1), 1), ((7,), 1), ((None, 0), 1)])
def test_one_combiner_failure_then_usage_then_limit(exits, combined):
    assert codes.combine_exits(*exits) == combined


def test_the_three_verdicts_in_cmd_receipts_all_go_through_the_combiner():
    """Read, not trusted: every verdict assigned in the --verify block is
    joined with combine_exits, and nothing is assigned to `code` bare after
    the key's own verdict."""
    source = (TREE / "sunglasses" / "cli.py").read_text(encoding="utf-8")
    block = source.split('if getattr(args, "verify", False):\n', 1)[1].split("return code", 1)[0]
    assigns = re.findall(r"\n\s+code = (.+)", block)
    assert assigns[0].startswith("_verify_key("), assigns
    assert all(a.startswith("codes.combine_exits(code, ") for a in assigns[1:]), assigns
    assert len(assigns) == 3, assigns
