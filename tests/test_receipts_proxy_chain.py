"""test_receipts_proxy_chain.py — the proxy writes its own chain (#172, T8's
proxy wiring). Red first, from WIRE_SPEC's proxy rows only.

Every assertion names the WIRE_SPEC line it comes from
(sunglasses/receipts/WIRE_SPEC.md at 0a49b76). Where the spec says nothing,
nothing is asserted here: the directory a proxy chain lives in, the condition
that turns it on, and the shape of a legacy log without a key are T8's to pick
and T11's to rule, so the chain is FOUND by its segments and its producer,
never by a path this file made up.

Layout is the shipped default and nothing else: the user's home holds the key,
and the proxy's state root is `serve.state_root()` with no override, which is
`~/.sunglasses/proxy`. SUNGLASSES_HOME points at the same home, so a writer
that finds the key through either route finds this one.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

from sunglasses.firewall import run_hook
from sunglasses.proxy import receipts as proxy_receipts
from sunglasses.proxy.serve import state_root
from sunglasses.receipts import chain, keys, verify, wire

TREE = pathlib.Path(__file__).resolve().parents[1]

CALL = json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "echo hello"},
    "session_id": "proxy-chain-test",
})

HEADER = {"session_id": "0" * 32, "budget_version": "sg-proxy-budget/1",
          "catalog_version": "sg-proxy-catalog/1",
          "contract_version": "GATE3_CONTRACT_v5.1"}

TOKEN = "0123456789abcdef"
MARKER = "diagnostic-marker-7f3a"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    home = tmp_path / ".sunglasses"
    monkeypatch.setenv("SUNGLASSES_HOME", str(home))
    keys.init(home)
    assert state_root() == home / "proxy"
    return home


def _session(run_id, *events):
    """One proxy session, opened, written and closed the way serve.py does."""
    log = proxy_receipts.Log(state_root(), run_id=run_id,
                             header=dict(HEADER, session_id=run_id))
    for kind, fields in events:
        log.event(kind, **fields)
    log.close()
    return log


def _chains(home):
    """Every directory under the home that holds chain segments."""
    return sorted({p.parent for p in home.rglob("segment-*.chain")})


def _records(directory):
    out = []
    for segment in sorted(directory.glob(chain.SEGMENT_GLOB)):
        for line in segment.read_bytes().splitlines(keepends=True):
            out.append(wire.decode_strict(line))
    return out


def _producers(directory):
    return {r["producer"] for r in _records(directory) if "producer" in r}


def _proxy_chains(home):
    return [d for d in _chains(home) if "proxy" in _producers(d)]


def _snapshot(root):
    return {p.relative_to(root): p.read_bytes()
            for p in sorted(pathlib.Path(root).rglob("*")) if p.is_file()}


def _public(home):
    return keys.public_path(home, keys.load(home).fingerprint).read_bytes()


RUN_A = "a" * 32
RUN_B = "b" * 32
SCAN = ("SCAN_STARTED", {"id_token": TOKEN})


# ── WIRE_SPEC L186-188: one chain per log, the proxy's own ──────────────────

def test_with_a_key_a_proxy_session_writes_its_own_chain(home):
    """L186-188 "The hook and each proxy log write separate chains, each in its
    own directory". A proxy session with the user's key leaves exactly one
    chain, every producer record in it says proxy, and it is not the hook's."""
    _session(RUN_A, SCAN)
    found = _proxy_chains(home)
    assert len(found) == 1, f"no proxy chain under {home}: {_chains(home)}"
    assert _producers(found[0]) == {"proxy"}
    assert found[0] != home / "receipts" / "hook"


def test_the_control_without_a_key_a_proxy_session_writes_no_chain(tmp_path, monkeypatch):
    """Control for the test above, not a spec assertion: the key is the only
    difference, so the red above is the wiring and not the fixture. Today's
    jsonl is where it has always been."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SUNGLASSES_HOME", str(tmp_path / ".sunglasses"))
    log = _session(RUN_A, SCAN)
    assert _chains(tmp_path) == []
    assert log.path.is_file()


def test_two_proxy_sessions_write_two_chains_each_with_its_own_sequence(home):
    """L186-188 "each proxy log ... its own sequence. There is no global
    sequence." Two sessions, two chains, and each opens at the genesis seq."""
    _session(RUN_A, SCAN)
    _session(RUN_B, SCAN)
    found = _proxy_chains(home)
    assert len(found) == 2, found
    for directory in found:
        assert _records(directory)[0]["seq"] == wire.GENESIS_SEQ


def test_a_hook_call_and_a_proxy_session_never_share_a_chain(home):
    """L186-188. Both producers sign with the one user key and still never
    land in one chain: the hook's chain holds only hook records, the proxy's
    only proxy records."""
    run_hook(CALL, home=home)
    _session(RUN_A, SCAN)
    by_producer = {frozenset(_producers(d)) for d in _chains(home)}
    assert by_producer == {frozenset({"hook"}), frozenset({"proxy"})}, by_producer


# ── WIRE_SPEC L186-190: the mirror of row 7 ─────────────────────────────────

def test_a_proxy_writer_refuses_a_chain_the_hook_opened(home):
    """L189-190 "a writer may never sign a suffix it did not write". The same
    key verifies the hook's seal, so the writer continues it today. It must
    refuse before any byte, and the hook's chain must be byte identical."""
    run_hook(CALL, home=home)
    hook_dir = home / "receipts" / "hook"
    before = _snapshot(hook_dir)
    with pytest.raises(ValueError):
        chain.Chain(hook_dir, keys.load(home), producer="proxy").write(
            [{"event": "item", "body": {"n": 1}}], seal="close")
    assert _snapshot(hook_dir) == before


def test_the_control_the_hook_continues_its_own_sealed_chain(home):
    """Control for the mirror: a second hook call continues the hook's own
    sealed chain, so the refusal above is about the producer, not the seal."""
    run_hook(CALL, home=home)
    run_hook(CALL, home=home)
    hook_dir = home / "receipts" / "hook"
    assert _producers(hook_dir) == {"hook"}
    report = verify.verify_log(hook_dir, _public(home))
    assert report.results["chain_integrity"] == "CHAIN_OK"


# ── WIRE_SPEC L108-109: sign at each observed session close ─────────────────

def test_a_closed_proxy_session_leaves_no_unsigned_tail(home):
    """L108-109 "Sign at creation ... each observed session close". After
    `close()` the proxy chain verifies with nothing after its last checkpoint."""
    _session(RUN_A, SCAN, ("SESSION_TORN_DOWN", {"reason_code": None}))
    found = _proxy_chains(home)
    assert len(found) == 1, f"no proxy chain under {home}"
    report = verify.verify_log(found[0], _public(home))
    assert report.results["chain_integrity"] == "CHAIN_OK"
    assert report.results["unsigned_tail"] == "NO_VISIBLE_TAIL"
    assert "purpose" in _records(found[0])[-1]


# ── WIRE_SPEC L58-59: diagnostics never inside signed bytes ─────────────────

def test_a_proxy_diagnostic_never_enters_the_chain(home):
    """L58-59 "diagnostics are displayed separately and never inside signed
    bytes". The fields the legacy log drops (exception, detail, text, content)
    stay out of the chain too: the marker is in no segment byte."""
    _session(RUN_A, SCAN, ("WATCHDOG", {
        "reason_code": "SCAN_EXCEPTION", "rule": "S3",
        "exception": MARKER, "detail": MARKER, "text": MARKER,
        "content": MARKER}))
    found = _proxy_chains(home)
    assert len(found) == 1, f"no proxy chain under {home}"
    for segment in found[0].glob(chain.SEGMENT_GLOB):
        assert MARKER.encode() not in segment.read_bytes()


# ── WIRE_SPEC L203-205: the verifier reports per chain ──────────────────────

def test_receipts_verify_reports_the_proxy_chain_beside_the_hook_chain(home):
    """L203 "The verifier reports per chain: five results for each chain".
    With a hook chain and a proxy chain in one home, `sunglasses receipts
    --verify` prints a log header and five results for each of the two."""
    run_hook(CALL, home=home)
    _session(RUN_A, SCAN)
    env = {**os.environ, "SUNGLASSES_HOME": str(home), "HOME": str(home.parent),
           "NO_COLOR": "1"}
    script = ("import runpy, sys\n"
              "sys.argv = ['sunglasses', 'receipts', '--verify']\n"
              "runpy.run_module('sunglasses.cli', run_name='__main__')\n")
    proc = subprocess.run([sys.executable, "-c", script], cwd=TREE, env=env,
                          capture_output=True, text=True)
    headers = [line for line in proc.stdout.splitlines()
               if " segment(s), key " in line]
    assert len(headers) == 2, proc.stdout[-2000:]
