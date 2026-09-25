"""Row 4 of the wire readiness note, the CLI half: no single boolean anywhere.

`sunglasses receipts --verify` over a signed log prints five results per log
and the three limitations, and no one word a stranger can quote as "the audit
is clean". That holds on the best possible log too: a trusted key, a retained
endpoint that matches, every call closed. Its exit code is 0, and the exit
code is still not a verdict printed as text.

The library half is pinned in sunglasses/receipts/tests/test_readiness_rows.py.
"""
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

pytest.importorskip("cryptography")

from sunglasses.receipts import chain, codes, keys, optin, wire   # noqa: E402

TREE = pathlib.Path(__file__).resolve().parents[1]
BANNED = ("clean", "all good", "passed", "verified ok", "trusted log", "no issues")


def _cli(home, *argv):
    env = dict(os.environ, SUNGLASSES_HOME=str(home))
    proc = subprocess.run([sys.executable, "-m", "sunglasses.cli", "receipts", *argv],
                          cwd=TREE, capture_output=True, text=True, env=env)
    return proc.returncode, re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout + proc.stderr)


def _signed_log(home):
    """`receipts init`, then two closed calls through the real writer."""
    keys.init(home)
    signer = keys.load(home)
    log = home / "receipts" / "hook"
    # The marker the real hook passes (R62 c: an unmarked hook log is a limit).
    writer = chain.Chain(log, signer, producer="hook", marker=optin.hook_marker(home))
    for n in range(2):
        writer.write([{"event": "in_flight", "body": {"eval_id": f"e{n}"}},
                      {"event": "decision", "body": {"eval_id": f"e{n}"}}],
                     seal="close")
    last = sorted(log.glob("segment-*.chain"))[-1].read_bytes().splitlines(True)[-1]
    record = wire.decode_strict(last)
    endpoint = {"chain_id": record["chain_id"], "seq": record["seq"],
                "hash": wire.record_hash(last)}
    return signer.fingerprint, endpoint


def _no_single_verdict(out):
    lowered = out.lower()
    for word in BANNED:
        assert word not in lowered, word
    for kind in codes.RESULT_KINDS:
        assert f"{kind}:" in out, kind
    for code in ("LC01", "LC02", "LC03"):
        assert code in out, code


def test_the_best_possible_log_still_prints_five_results_not_a_verdict(tmp_path):
    home = tmp_path / "home"
    fingerprint, endpoint = _signed_log(home)
    code, out = _cli(home, "--verify", "--fingerprint", fingerprint,
                     "--endpoint", json.dumps(endpoint))
    assert "KEY_TRUSTED" in out and "ENDPOINT_CONFIRMED" in out, out
    assert code == 0, out
    _no_single_verdict(out)


@pytest.mark.parametrize("extra", [(), ("--fingerprint", "0" * 64)])
def test_an_unconfirmed_log_prints_five_results_and_exits_non_zero(tmp_path, extra):
    home = tmp_path / "home"
    _signed_log(home)
    code, out = _cli(home, "--verify", *extra)
    assert code != 0, out
    _no_single_verdict(out)
