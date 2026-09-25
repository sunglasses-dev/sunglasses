"""test_receipts_hook_not_proxy_chain.py — a hook call never writes into a
proxy chain (#172 readiness row 7, second half).

WIRE_SPEC "one chain per log" (T9 ruling 15): the hook and each proxy log write
separate chains, each in its own directory with its own lock and sequence,
because a writer may never sign a suffix it did not write. Today that holds
because the hook picks `receipts/hook`. Nothing in the writer holds it: both
producers sign with the user's one key, so a hook writer pointed at a sealed
proxy chain finds a seal that verifies under its own key and continues the
proxy's segment. The rule lives in one call site's choice of directory.

So two halves. The hook path, end to end, leaves a proxy chain byte identical.
And the writer refuses a chain another producer opened, before any byte, so the
rule survives the next caller that gets the directory wrong.
"""
import json
import pathlib

import pytest

from sunglasses.firewall import run_hook
from sunglasses.receipts import chain, keys, wire

CALL = json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "echo hello"},
    "session_id": "row7-test",
})


@pytest.fixture
def home(tmp_path):
    home = tmp_path / "sunglasses-home"
    keys.init(home)
    return home


def _proxy_chain(home, directory):
    """A sealed chain the proxy opened: genesis, one item, a close."""
    chain.Chain(directory, keys.load(home), producer="proxy").write(
        [{"event": "item", "body": {"n": 1}}], seal="close")
    return directory


def _snapshot(root):
    return {p.relative_to(root): p.read_bytes()
            for p in sorted(pathlib.Path(root).rglob("*")) if p.is_file()}


def _producers(directory):
    found = set()
    for segment in sorted(directory.glob(chain.SEGMENT_GLOB)):
        for line in segment.read_bytes().splitlines(keepends=True):
            record = wire.decode_strict(line)
            if "producer" in record:
                found.add(record["producer"])
    return found


def test_a_hook_call_leaves_a_proxy_chain_byte_identical(home):
    proxy = _proxy_chain(home, home / "receipts" / "proxy")
    before = _snapshot(proxy)
    run_hook(CALL, home=home)
    run_hook(CALL, home=home)
    assert _snapshot(proxy) == before
    assert _producers(proxy) == {"proxy"}
    assert _producers(home / "receipts" / "hook") == {"hook"}


def test_the_control_the_proxy_writer_continues_its_own_sealed_chain(home):
    """Without this, the refusal below could be a chain nobody can continue."""
    proxy = _proxy_chain(home, home / "receipts" / "proxy")
    segments = sorted(proxy.glob(chain.SEGMENT_GLOB))
    size = segments[-1].stat().st_size
    chain.Chain(proxy, keys.load(home), producer="proxy").write(
        [{"event": "item", "body": {"n": 2}}], seal="close")
    assert sorted(proxy.glob(chain.SEGMENT_GLOB)) == segments
    assert segments[-1].stat().st_size > size


def test_a_hook_writer_refuses_a_proxy_chain_and_writes_nothing(home):
    proxy = _proxy_chain(home, home / "receipts" / "proxy")
    before = _snapshot(proxy)
    writer = chain.Chain(proxy, keys.load(home), producer="hook")
    with pytest.raises(ValueError):
        writer.write([{"event": "in_flight", "body": {"eval_id": "x"}}], seal="close")
    assert _snapshot(proxy) == before
    assert _producers(proxy) == {"proxy"}
