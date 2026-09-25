"""
test_receipts_verify_log_path.py — `receipts --verify --log PATH` verifies a
log someone else sent, and never reads the verifier's own home (T9 ruling 47,
outsider rehearsal gap G3; exits per ruling 48).

At 5480cdd `--verify` read only `$SUNGLASSES_HOME/receipts` and the proxy state
root, so an outsider had to plant a received log in their own home. A received
HOOK log there made `optin.opted_in` true, and the verifier printed
KEY_UNUSABLE for a key the outsider never had and exited 1, although the log
itself verified.

With `--log`, the home is never consulted: not its logs, not its keys, not its
signing state. The public key is `--public-key PATH`, or else the one `*.pub`
file inside the log directory. The key beside a log is portability, not trust,
so without `--fingerprint` it is KEY_UNTRUSTED, a limit (exit 3).
"""
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

pytest.importorskip("cryptography")

from sunglasses.receipts import chain, codes, keys, wire  # noqa: E402

TREE = pathlib.Path(__file__).resolve().parents[1]


def _cli(home, *argv):
    env = dict(os.environ, SUNGLASSES_HOME=str(home))
    proc = subprocess.run([sys.executable, "-m", "sunglasses.cli", "receipts", *argv],
                          cwd=TREE, capture_output=True, text=True, env=env)
    return proc.returncode, re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout + proc.stderr)


@pytest.fixture
def sent(tmp_path):
    """A hook log written in the SENDER's home and copied out with its public
    key beside it, the way it is handed to someone else."""
    sender = tmp_path / "sender"
    keys.init(sender)
    signer = keys.load(sender)
    log = sender / "receipts" / "hook"
    writer = chain.Chain(log, signer, producer="hook")
    writer.write([{"event": "in_flight", "body": {"eval_id": "e1"}},
                  {"event": "decision", "body": {"eval_id": "e1"}}], seal="close")
    received = tmp_path / "inbox" / "hook"
    received.mkdir(parents=True)
    for segment in log.glob("segment-*.chain"):
        (received / segment.name).write_bytes(segment.read_bytes())
    pub = sender / keys.KEY_DIR / keys.PUBLIC_DIR / f"{signer.fingerprint}.pub"
    (received / pub.name).write_bytes(pub.read_bytes())
    lines = sorted(received.glob("segment-*.chain"))[-1].read_bytes().splitlines(
        keepends=True)
    last = max(i for i, line in enumerate(lines)
               if wire.decode_strict(line)["event"] == "checkpoint")
    endpoint = json.dumps({"chain_id": wire.decode_strict(lines[0])["chain_id"],
                           "seq": last, "hash": wire.record_hash(lines[last])})
    return received, signer.fingerprint, endpoint, pub


@pytest.fixture
def verifier_home(tmp_path):
    """The verifier's own home: it has a key of its own and a hook chain whose
    signing key is gone, so any read of it would print KEY_UNUSABLE."""
    home = tmp_path / "verifier"
    keys.init(home)
    signer = keys.load(home)
    chain.Chain(home / "receipts" / "hook", signer, producer="hook").write(
        [{"event": "in_flight", "body": {"eval_id": "mine"}}], seal="close")
    for private in (home / keys.KEY_DIR).glob("*"):
        if private.is_file():
            private.unlink()
    return home


def test_a_foreign_log_with_its_fingerprint_and_endpoint_exits_0(sent, verifier_home):
    log, fp, endpoint, _ = sent
    code, out = _cli(verifier_home, "--verify", "--log", str(log),
                     "--fingerprint", fp, "--endpoint", endpoint)
    assert "key_trust: KEY_TRUSTED" in out, out
    assert "lifecycle: LIFECYCLE_COMPLETE" in out, out
    assert "KEY_UNUSABLE" not in out
    assert code == 0, out


def test_the_home_is_never_read_with_log(sent, verifier_home):
    """The control for the row above: the same home, read the old way, does
    print KEY_UNUSABLE, so its absence above is the flag's doing."""
    code, out = _cli(verifier_home, "--verify")
    assert "KEY_UNUSABLE" in out, out
    log, fp, endpoint, _ = sent
    code, out = _cli(verifier_home, "--verify", "--log", str(log), "--fingerprint", fp)
    assert "KEY_UNUSABLE" not in out, out
    assert out.count("key_trust: ") == 2, out      # one log, one segment


def test_no_fingerprint_is_key_untrusted_a_limit_exit_3(sent, verifier_home):
    log, _, endpoint, _ = sent
    code, out = _cli(verifier_home, "--verify", "--log", str(log),
                     "--endpoint", endpoint)
    assert "key_trust: KEY_UNTRUSTED" in out, out
    assert code == codes.EXIT_LIMIT == 3, out
    code, out = _cli(verifier_home, "--verify", "--strict", "--log", str(log),
                     "--endpoint", endpoint)
    assert code == 1, out


def test_a_flipped_byte_exits_1(sent, verifier_home):
    log, fp, endpoint, _ = sent
    segment = sorted(log.glob("segment-*.chain"))[0]
    data = bytearray(segment.read_bytes())
    at = data.index(b'"e1"')
    data[at + 1:at + 3] = b"E1"
    segment.write_bytes(bytes(data))
    code, out = _cli(verifier_home, "--verify", "--log", str(log),
                     "--fingerprint", fp, "--endpoint", endpoint)
    assert "chain_integrity: CHAIN_OK" not in out.split("-- segment")[0], out
    assert code == 1, out


def test_a_missing_log_path_fails_and_never_falls_back_to_home(tmp_path, verifier_home):
    code, out = _cli(verifier_home, "--verify", "--log", str(tmp_path / "nowhere"))
    assert code == 1, out
    assert "KEY_UNUSABLE" not in out
    assert "hook: " not in out, out


def test_a_directory_with_no_segments_fails(tmp_path, verifier_home):
    empty = tmp_path / "empty"
    empty.mkdir()
    code, out = _cli(verifier_home, "--verify", "--log", str(empty))
    assert code == 1, out
    assert "hook: " not in out, out


def test_public_key_names_the_key_and_the_log_needs_none_beside_it(sent, verifier_home,
                                                                    tmp_path):
    log, fp, endpoint, pub = sent
    kept = tmp_path / "kept.pub"
    kept.write_bytes(pub.read_bytes())
    for beside in log.glob("*.pub"):
        beside.unlink()
    code, out = _cli(verifier_home, "--verify", "--log", str(log))
    assert code == 1, out
    assert "no public key" in out.lower(), out
    code, out = _cli(verifier_home, "--verify", "--log", str(log),
                     "--public-key", str(kept), "--fingerprint", fp,
                     "--endpoint", endpoint)
    assert code == 0, out


def test_a_wrong_public_key_is_not_trusted_by_its_fingerprint(sent, verifier_home,
                                                               tmp_path):
    log, fp, endpoint, _ = sent
    other = tmp_path / "other"
    keys.init(other)
    wrong = next((other / keys.KEY_DIR / keys.PUBLIC_DIR).glob("*.pub"))
    code, out = _cli(verifier_home, "--verify", "--log", str(log),
                     "--public-key", str(wrong), "--fingerprint", fp,
                     "--endpoint", endpoint)
    assert "EXPECTED_KEY_MISMATCH" in out, out
    assert code == 1, out


def test_a_missing_public_key_path_fails(sent, verifier_home, tmp_path):
    log, fp, _, _ = sent
    code, out = _cli(verifier_home, "--verify", "--log", str(log),
                     "--public-key", str(tmp_path / "nope.pub"), "--fingerprint", fp)
    assert code == 1, out


def test_a_key_file_that_is_not_32_bytes_fails_without_a_traceback(sent, verifier_home,
                                                                   tmp_path):
    log, fp, _, _ = sent
    short = tmp_path / "short.pub"
    short.write_bytes(b"\x01" * 31)
    code, out = _cli(verifier_home, "--verify", "--log", str(log),
                     "--public-key", str(short), "--fingerprint", fp)
    assert code == 1, out
    assert "Traceback" not in out, out
    assert "32" in out, out


def test_log_and_public_key_without_their_partner_are_usage_errors(sent, verifier_home):
    log, _, _, pub = sent
    assert _cli(verifier_home, "--log", str(log))[0] == codes.EXIT_USAGE == 2
    assert _cli(verifier_home, "--verify", "--public-key", str(pub))[0] == 2
