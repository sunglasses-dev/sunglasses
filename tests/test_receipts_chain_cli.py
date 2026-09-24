"""
test_receipts_chain_cli.py — `sunglasses receipts init` and `--verify` over
signed chains (#172).

T9 RULING 11: the chain IS the log when enabled. With the extra missing, or
before the user has run `receipts init`, nothing changes for an existing
install, and `--verify` calls a legacy log UNSIGNED, never a failure. The key is
made only by an explicit `receipts init`, never on a first write.

T9 RULING 15: one chain per log, each verified alone with its own five results.
The key that sits beside a log gives portability, not trust: it is reported
KEY_UNTRUSTED unless the user supplies a fingerprint obtained elsewhere.

Every test runs the real CLI the way a user does.
"""
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

from sunglasses.receipts import chain, keys

TREE = pathlib.Path(__file__).resolve().parents[1]


def _cli(home, *argv, no_crypto=None):
    """(exit code, plain text). `no_crypto` is a directory whose fake
    `cryptography` refuses to import: the extra is not installed."""
    env = dict(os.environ, SUNGLASSES_HOME=str(home))
    if no_crypto is not None:
        env["PYTHONPATH"] = os.pathsep.join(
            [str(no_crypto), str(TREE), env.get("PYTHONPATH", "")])
    proc = subprocess.run([sys.executable, "-m", "sunglasses.cli", "receipts", *argv],
                          cwd=TREE, capture_output=True, text=True, env=env)
    return proc.returncode, re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout + proc.stderr)


@pytest.fixture
def home(tmp_path):
    return tmp_path / "sunglasses-home"


@pytest.fixture
def no_crypto(tmp_path):
    fake = tmp_path / "no-crypto" / "cryptography"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text(
        "raise ImportError('cryptography is not installed (test)')\n")
    return fake.parent


def _legacy(home):
    """A clean legacy day: one call, opening and terminal paired."""
    d = home / "receipts"
    d.mkdir(parents=True, exist_ok=True)
    rows = [{"kind": "in_flight", "eval_id": "e1", "ts": "2026-09-24T01:00:00",
             "tool_name": "Bash"},
            {"kind": "decision", "eval_id": "e1", "ts": "2026-09-24T01:00:00",
             "tool_name": "Bash", "decision": "allow"}]
    (d / "2026-09-24.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))


def _hook_chain(home, calls=2):
    signer = keys.load(home)
    log = home / "receipts" / "hook"
    writer = chain.Chain(log, signer, producer="hook")
    for n in range(calls):
        writer.write([{"event": "in_flight", "body": {"eval_id": f"e{n}"}},
                      {"event": "decision", "body": {"eval_id": f"e{n}"}}],
                     seal="close")
    return log, signer.fingerprint


# ── init: the user's key, only when asked ─────────────────────────────────────

def test_init_makes_the_users_key_and_prints_its_fingerprint(home):
    code, out = _cli(home, "init")
    assert code == 0, out
    signer = keys.load(home)
    assert signer is not None
    assert signer.fingerprint in out
    assert keys.public_path(home, signer.fingerprint).exists()


def test_a_second_init_refuses_and_keeps_the_first_key(home):
    _cli(home, "init")
    before = keys.private_path(home).read_bytes()
    code, out = _cli(home, "init")
    assert code != 0
    assert "already" in out.lower()
    assert keys.private_path(home).read_bytes() == before
    assert len(list((home / "keys").glob("receipt-*.ed25519"))) == 1


@pytest.mark.parametrize("argv", [(), ("--verify",), ("--today",)])
def test_reading_or_verifying_never_makes_a_key(home, argv):
    _legacy(home)
    _cli(home, *argv)
    assert not (home / "keys").exists()


def test_init_without_the_extra_says_what_to_install_and_makes_nothing(home, no_crypto):
    code, out = _cli(home, "init", no_crypto=no_crypto)
    assert code != 0
    assert "sunglasses[receipts]" in out
    assert not (home / "keys").exists()


# ── --verify on a legacy log: UNSIGNED, never a failure ──────────────────────

def test_a_legacy_log_is_called_unsigned_and_its_exit_code_is_unchanged(home):
    _legacy(home)
    code, out = _cli(home, "--verify")
    assert code == 0, out                         # the lifecycle verdict, as before
    assert "LEGACY_UNSIGNED" in out
    assert "No orphans." in out


def test_without_the_extra_a_legacy_log_verifies_exactly_as_before(home, no_crypto):
    _legacy(home)
    code, out = _cli(home, "--verify", no_crypto=no_crypto)
    assert code == 0, out
    assert "LEGACY_UNSIGNED" in out
    assert "No orphans." in out


# ── --verify on a chain: five results per log, printed per log ───────────────

def test_a_sealed_hook_chain_prints_its_five_results(home):
    _cli(home, "init")
    _hook_chain(home)
    code, out = _cli(home, "--verify")
    assert "hook: 1 segment(s)" in out
    assert "chain_integrity: CHAIN_OK" in out
    assert "unsigned_tail: NO_VISIBLE_TAIL" in out
    assert "lifecycle: LIFECYCLE_COMPLETE" in out
    # The key beside the log is portability, not trust, and the extent is
    # unknown without a retained endpoint: an unknown is not a pass.
    assert "key_trust: KEY_UNTRUSTED" in out
    assert "expected_endpoint: HISTORY_EXTENT_UNKNOWN" in out
    assert code == 1
    for word in ("PASS", "VALID", "verified OK"):
        assert word not in out


def test_a_fingerprint_from_elsewhere_makes_the_key_trusted(home):
    _cli(home, "init")
    _, fp = _hook_chain(home)
    code, out = _cli(home, "--verify", "--fingerprint", fp)
    assert "key_trust: KEY_TRUSTED" in out
    code, out = _cli(home, "--verify", "--fingerprint", "0" * 64)
    assert "key_trust: EXPECTED_KEY_MISMATCH" in out
    assert code == 1


def test_a_retained_endpoint_is_confirmed_and_then_the_run_can_pass(home):
    _cli(home, "init")
    log, fp = _hook_chain(home)
    from sunglasses.receipts import wire
    segment = sorted(log.glob("segment-*.chain"))[-1]
    lines = segment.read_bytes().splitlines(keepends=True)
    last = max(i for i, line in enumerate(lines)
               if wire.decode_strict(line)["event"] == "checkpoint")
    endpoint = {"chain_id": wire.decode_strict(lines[0])["chain_id"],
                "seq": last, "hash": wire.record_hash(lines[last])}
    code, out = _cli(home, "--verify", "--fingerprint", fp,
                     "--endpoint", json.dumps(endpoint))
    assert "expected_endpoint: ENDPOINT_CONFIRMED" in out, out
    assert code == 0, out
    code, out = _cli(home, "--verify", "--fingerprint", fp,
                     "--endpoint", json.dumps(dict(endpoint, hash="0" * 64)))
    assert "expected_endpoint: CHECKPOINT_MISMATCH" in out
    assert code == 1


def test_an_edited_chain_fails_and_a_clean_legacy_log_does_not_hide_it(home):
    _legacy(home)
    _cli(home, "init")
    log, fp = _hook_chain(home)
    segment = sorted(log.glob("segment-*.chain"))[0]
    data = bytearray(segment.read_bytes())
    at = data.index(b'"e0"')
    data[at + 1:at + 3] = b"E0"
    segment.write_bytes(bytes(data))
    code, out = _cli(home, "--verify", "--fingerprint", fp)
    assert code == 1
    assert "chain_integrity: CHAIN_OK" not in out.split("-- segment")[0]
    assert "LEGACY_UNSIGNED" in out


def test_each_log_is_verified_alone(home):
    _cli(home, "init")
    _hook_chain(home)
    signer = keys.load(home)
    proxy = home / "receipts" / "proxy-srv"
    chain.Chain(proxy, signer, producer="proxy").write(
        [{"event": "ADMITTED", "body": {"eval_id": "p1"}}], seal="close")
    code, out = _cli(home, "--verify")
    assert "hook: 1 segment(s)" in out
    assert "proxy-srv: 1 segment(s)" in out
    assert out.count("chain_integrity: ") >= 4    # two logs + their segments


def test_a_chain_with_no_key_to_check_it_is_never_called_intact(home):
    _cli(home, "init")
    _hook_chain(home)
    for path in (home / "keys").rglob("*"):
        if path.is_file():
            path.unlink()
    code, out = _cli(home, "--verify")
    assert code == 1
    assert "CHAIN_OK" not in out
    assert "no public key" in out.lower()


def test_without_the_extra_a_chain_is_reported_unverified_never_skipped(home, no_crypto):
    _cli(home, "init")
    _hook_chain(home)
    code, out = _cli(home, "--verify", no_crypto=no_crypto)
    assert code == 1
    assert "CHAIN_OK" not in out
    assert "sunglasses[receipts]" in out
    assert "hook" in out
