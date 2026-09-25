"""T9 rulings 59 and 60, the two 0.6.1 design rows left for after the freeze.

Q2. An opted-in home whose hook chain lost its segments read NO_LOG, exit 3,
the same as a home that never wrote: the verifier could not tell a wiped log
from one never begun. The hook's first genesis now leaves a signed marker,
`keys/log-hook.genesis`, naming that chain and its time, under a signing domain
of its own. With the marker there, a hook log that does not open with the
chain it names lacks what it must carry: that is LOG_MISSING, a failure, exit 1
in both modes. A marker that cannot be read is PATH_UNREADABLE; one whose
signature does not verify is a failure naming why, never "missing". With no
marker the verifier still cannot tell, and NO_LOG stays the limit it was.

Q3. A proxy run in a home that never opted in writes `<run id>.jsonl`, and
neither command showed it. The exit follows the claim (ruling 60): a log the
verifier DISCOVERED on the home walk, with no marker saying it should have been
signed, is LOG_UNCHAINED, a limit, exit 3 and 1 under `--strict`. That holds
for the run's `.jsonl` and for the hook's legacy day files alike. A log the
caller SUPPLIED with `--log` and no signatures stays a failure. Plain
`receipts` names the run and stays exit 0.

Every row runs the real command, `python -m sunglasses.cli receipts`, on a
home built by the real hook and the real proxy.
"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

from sunglasses.firewall import run_hook
from sunglasses.proxy import receipts as proxy_receipts
from sunglasses.receipts import codes, keys, wire

TREE = pathlib.Path(__file__).resolve().parents[1]
STRICT = [pytest.param([], id="verify"), pytest.param(["--strict"], id="strict")]


def _call(n=0):
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": f"echo {n}"},
                       "session_id": "r59-test"})


def _user(home):
    return home.parent / "user"


def _proxy_root(home):
    """The proxy's default state root, ~/.sunglasses/proxy, under the HOME a
    row gives its child: a row never reads the user's own proxy logs."""
    return _user(home) / ".sunglasses" / "proxy"


def _env(home):
    return {**os.environ, "SUNGLASSES_HOME": str(home), "HOME": str(_user(home)),
            "PYTHONPATH": str(TREE)}


def _receipts(home, *argv):
    proc = subprocess.run([sys.executable, "-m", "sunglasses.cli", "receipts", *argv],
                          cwd=TREE, env=_env(home), capture_output=True, text=True)
    return proc.returncode, re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout + proc.stderr)


def _proxy_run(home):
    """One real proxy run at the default state root. Returns its log entry."""
    root = _proxy_root(home)
    before = set(root.joinpath("receipts").iterdir()) if root.joinpath("receipts").is_dir() else set()
    script = ("import sys\nfrom sunglasses.proxy import serve\n"
              f"sys.exit(serve.main(['--state-root', {str(root)!r}, '--', "
              f"{sys.executable!r}, '-c', 'import sys; sys.stdin.read()']))\n")
    subprocess.run([sys.executable, "-c", script], cwd=TREE, env=_env(home),
                   input=b"", capture_output=True, timeout=60, check=False)
    new = sorted(set(root.joinpath("receipts").iterdir()) - before)
    assert len(new) == 1, new
    return new[0]


def _segments(log):
    return sorted(log.glob("segment-*.chain"))


@pytest.fixture
def opted_in(tmp_path):
    """A home that opted in and wrote: a key and three sealed hook calls."""
    home = tmp_path / "sunglasses-home"
    _user(home).mkdir(parents=True)
    keys.init(home)
    for n in range(3):
        run_hook(_call(n), home=home)
    assert _segments(home / "receipts" / "hook")
    return home


@pytest.fixture
def never(tmp_path):
    """A home that never opted in."""
    home = tmp_path / "sunglasses-home"
    _user(home).mkdir(parents=True)
    return home


MARKER = "log-hook.genesis"


def _markers(home):
    return sorted((home / keys.KEY_DIR).glob("*.genesis"))


def _hook_ids(home):
    ids = set()
    for s in _segments(home / "receipts" / "hook"):
        with open(s, "rb") as handle:
            ids.add(json.loads(handle.readline())["chain_id"])
    return ids


# ── The two codes, and their classes ──────────────────────────────────────────

def test_log_missing_is_a_failure_code():
    assert "LOG_MISSING" in codes.CODES
    assert codes.CLASS["LOG_MISSING"] == codes.FAIL
    assert codes.exit_for("LOG_MISSING") == codes.EXIT_FAIL
    assert codes.exit_for("LOG_MISSING", strict=True) == codes.EXIT_FAIL
    assert codes.untagged() == []


def test_log_unchained_is_a_limit_code():
    assert "LOG_UNCHAINED" in codes.CODES
    assert codes.CLASS["LOG_UNCHAINED"] == codes.LIMIT
    assert codes.exit_for("LOG_UNCHAINED") == codes.EXIT_LIMIT
    assert codes.exit_for("LOG_UNCHAINED", strict=True) == codes.EXIT_FAIL
    assert codes.CLASS["LEGACY_UNSIGNED"] == codes.FAIL        # the supplied log's code


# ── Q2: the marker ────────────────────────────────────────────────────────────

def test_init_alone_writes_no_marker(tmp_path):
    """Nothing is written yet, so nothing can be missing: init then verify is
    NO_LOG, never a false LOG_MISSING."""
    home = tmp_path / "sunglasses-home"
    keys.init(home)
    assert _markers(home) == []


def test_the_first_hook_genesis_writes_one_marker_naming_its_chain(opted_in):
    found = _markers(opted_in)
    assert [m.name for m in found] == [MARKER], found
    raw = found[0].read_bytes()
    marker = wire.decode_strict(raw)                   # one canonical line
    first = _segments(opted_in / "receipts" / "hook")[0]
    with open(first, "rb") as handle:
        genesis = json.loads(handle.readline())
    assert marker["chain_id"] == genesis["chain_id"]
    assert marker["key_id"] == genesis["key_id"]
    assert marker["t_wall_ns"] == genesis["t_wall_ns"]
    assert isinstance(marker["signature"], str)


def test_the_marker_is_signed_under_its_own_domain(opted_in):
    (found,) = _markers(opted_in)
    marker = wire.decode_strict(found.read_bytes())
    signature = bytes.fromhex(marker["signature"])
    public = keys.public_key(opted_in, marker["key_id"])
    public.verify(signature, wire.marker_signing_bytes(marker))
    assert wire.MARKER_DOMAIN not in (wire.RECORD_DOMAIN, wire.CHECKPOINT_DOMAIN,
                                      wire.FINGERPRINT_DOMAIN)
    with pytest.raises(Exception):                     # never a checkpoint's bytes
        public.verify(signature, wire.checkpoint_signing_bytes(marker))


def test_a_later_write_never_rewrites_the_marker(opted_in):
    (marker,) = _markers(opted_in)
    before = marker.read_bytes()
    for s in _segments(opted_in / "receipts" / "hook"):
        s.unlink()
    run_hook(_call(9), home=opted_in)              # a fresh chain opens
    assert _markers(opted_in) == [marker]
    assert marker.read_bytes() == before


def test_a_marker_already_there_is_never_an_error_and_never_replaced(tmp_path):
    """Ruling 60 (a): the writer proceeds, and the verifier reports it."""
    home = tmp_path / "sunglasses-home"
    _user(home).mkdir(parents=True)
    keys.init(home)
    planted = home / keys.KEY_DIR / MARKER
    planted.write_bytes(b"not ours\n")
    run_hook(_call(0), home=home)
    assert _segments(home / "receipts" / "hook")       # the hook still wrote
    assert planted.read_bytes() == b"not ours\n"
    code, out = _receipts(home, "--verify")
    assert code == 1, out
    assert MARKER in out and "Traceback" not in out, out


# ── Q2: the verdicts ─────────────────────────────────────────────────────────

def _wipe_segments(home):
    for s in _segments(home / "receipts" / "hook"):
        s.unlink()


def _remove_log(home):
    shutil.rmtree(home / "receipts" / "hook")


def _wipe_and_rewrite(home):
    _wipe_segments(home)
    run_hook(_call(9), home=home)


@pytest.mark.parametrize("strict", STRICT)
@pytest.mark.parametrize("damage", [_wipe_segments, _remove_log, _wipe_and_rewrite],
                         ids=["segments-deleted", "log-removed", "wiped-then-rewritten"])
def test_a_marked_hook_log_without_its_chain_is_log_missing(opted_in, damage, strict):
    damage(opted_in)
    code, out = _receipts(opted_in, "--verify", *strict)
    assert "LOG_MISSING" in out, out
    assert "NO_LOG" not in out, out
    assert code == 1, out
    assert "Traceback" not in out, out


@pytest.mark.parametrize("strict", STRICT)
def test_log_missing_beside_a_healthy_proxy_run_still_fails(opted_in, strict):
    run = _proxy_run(opted_in)
    assert run.is_dir() and _segments(run)
    _wipe_segments(opted_in)
    code, out = _receipts(opted_in, "--verify", *strict)
    assert "LOG_MISSING" in out, out
    assert "CHAIN_OK" in out, out                  # the run is still verified
    assert code == 1, out


@pytest.mark.parametrize("strict", STRICT)
def test_a_marker_that_does_not_verify_is_a_failure_never_missing(opted_in, strict):
    (marker,) = _markers(opted_in)
    record = wire.decode_strict(marker.read_bytes())
    record["t_wall_ns"] += 1
    marker.write_bytes(wire.encode(record))         # canonical, signature stale
    code, out = _receipts(opted_in, "--verify", *strict)
    assert code == 1, out
    assert "SIGNATURE_INVALID" in out and MARKER in out, out
    assert "LOG_MISSING" not in out, out


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a 000 file")
@pytest.mark.parametrize("strict", STRICT)
def test_a_marker_that_cannot_be_read_is_path_unreadable(opted_in, strict):
    (marker,) = _markers(opted_in)
    marker.chmod(0)
    try:
        code, out = _receipts(opted_in, "--verify", *strict)
    finally:
        marker.chmod(0o600)
    assert "PATH_UNREADABLE" in out and MARKER in out, out
    assert "LOG_MISSING" not in out and "Traceback" not in out, out
    assert code == 1, out


# Controls: what the marker must not change.

@pytest.mark.parametrize("strict", STRICT)
def test_control_init_only_is_still_no_log(tmp_path, strict):
    home = tmp_path / "sunglasses-home"
    _user(home).mkdir(parents=True)
    keys.init(home)
    code, out = _receipts(home, "--verify", *strict)
    assert "NO_LOG" in out and "LOG_MISSING" not in out, out
    assert code == (1 if strict else 3), out


@pytest.mark.parametrize("strict", STRICT)
def test_control_a_healthy_marked_log_is_unchanged(opted_in, strict):
    assert _markers(opted_in)
    code, out = _receipts(opted_in, "--verify", *strict)
    assert "CHAIN_OK" in out and "LOG_MISSING" not in out, out
    assert code == (1 if strict else 3), out


def test_control_an_unmarked_wiped_log_stays_the_no_log_limit(opted_in):
    """No marker, no way to tell: the ruling keeps NO_LOG for this."""
    for marker in _markers(opted_in):
        marker.unlink()
    _wipe_segments(opted_in)
    code, out = _receipts(opted_in, "--verify")
    assert "NO_LOG" in out and "LOG_MISSING" not in out, out
    assert code == 3, out


def test_control_plain_receipts_is_not_a_verdict(opted_in):
    _wipe_segments(opted_in)
    code, out = _receipts(opted_in)
    assert code == 0, out


# ── Q3: a discovered log with no chain ───────────────────────────────────────

def _run_jsonl(home):
    entry = _proxy_run(home)
    assert entry.is_file() and proxy_receipts.is_run_log_name(entry.stem), entry
    return entry


@pytest.mark.parametrize("strict", STRICT)
def test_a_run_jsonl_alone_is_log_unchained(never, strict):
    entry = _run_jsonl(never)
    assert entry.stat().st_size > 0
    code, out = _receipts(never, "--verify", *strict)
    assert "LOG_UNCHAINED" in out and entry.stem in out, out
    assert "NO_LOG" not in out and "LEGACY_UNSIGNED" not in out, out
    assert code == (1 if strict else 3), out


@pytest.mark.parametrize("strict", STRICT)
def test_an_empty_run_jsonl_is_still_a_run_log(never, strict):
    entry = _run_jsonl(never)
    entry.write_bytes(b"")
    code, out = _receipts(never, "--verify", *strict)
    assert "LOG_UNCHAINED" in out and entry.stem in out, out
    assert code == (1 if strict else 3), out


@pytest.mark.parametrize("strict", STRICT)
def test_an_older_run_jsonl_beside_healthy_chains_is_named(opted_in, tmp_path, strict):
    other = tmp_path / "o" / "sunglasses-home"
    _user(other).mkdir(parents=True)
    entry = _run_jsonl(other)
    run = _proxy_run(opted_in)
    shutil.copy2(entry, run.parent / entry.name)
    code, out = _receipts(opted_in, "--verify", *strict)
    assert "LOG_UNCHAINED" in out and entry.stem in out, out
    assert "CHAIN_OK" in out, out
    assert code == (1 if strict else 3), out


@pytest.mark.parametrize("strict", STRICT)
def test_a_legacy_day_file_is_log_unchained(never, strict):
    """The two shapes agree (ruling 60): a clean day file the walk found is
    the same limit as a run's, joined to its lifecycle verdict."""
    run_hook(_call(0), home=never)
    assert sorted((never / "receipts").glob("*.jsonl"))
    code, out = _receipts(never, "--verify", *strict)
    assert "LOG_UNCHAINED" in out and "LEGACY_UNSIGNED" not in out, out
    assert code == (1 if strict else 3), out


def test_plain_receipts_names_a_run_jsonl(never):
    entry = _run_jsonl(never)
    code, out = _receipts(never)
    assert entry.stem in out, out
    assert code == 0, out


@pytest.mark.parametrize("strict", STRICT)
def test_control_a_supplied_run_jsonl_still_fails(never, strict):
    """The claim is the caller's: a log handed in with --log is never capped
    at a limit."""
    entry = _run_jsonl(never)
    code, out = _receipts(never, "--verify", "--log", str(entry), *strict)
    assert code == 1, out
    assert "LOG_UNCHAINED" not in out and "Traceback" not in out, out


# Controls: a name that is not a run's is not a log.

@pytest.mark.parametrize("name", ["notes.jsonl", "0" * 32 + ".txt",
                                  "A" * 32 + ".jsonl", "0" * 31 + ".jsonl"])
def test_control_a_stray_name_is_not_a_run_log(never, name):
    entry = _run_jsonl(never)
    entry.rename(entry.with_name(name))
    code, out = _receipts(never, "--verify")
    assert "LOG_UNCHAINED" not in out, out
    assert "NO_LOG" in out, out
    assert code == 3, out
