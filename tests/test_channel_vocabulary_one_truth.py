"""The channel vocabulary is published TWICE, so it drifted.

`scan_text`'s inputSchema enum advertised nine channels while `scanner_info`
reported five, and both come out of the same server. The five were a hardcoded
literal inside `SunglassesEngine.info()` that nothing compared against
`DOCUMENTED_CHANNELS`, so the two surfaces were free to disagree forever -- the
same shape as any fact written where nothing re-executes it.

Measured on 697ab21 before the fix: all nine channels are accepted and routed
(`tool_output` alone is declared by 622 loaded patterns), an unknown name raises
ValueError, and `code`/`prompt` are alias UNIONS that keep their own patterns
and additionally match their canonical channel. So the nine was right and the
five was wrong; the fix makes `info()` derive its list instead of repeating it.

These tests read both surfaces from the RUNNING server over stdio, not from the
module. The defect being fixed is a second copy of a fact, so an in-process
import would be a third copy rather than a check -- and it would miss a
packaging or serialization difference between what the code holds and what a
client is actually told.
"""
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sunglasses.engine import SunglassesEngine

REPO_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

# Reachable, undocumented, and deliberately left that way (see the comment at
# DOCUMENTED_CHANNELS). Dropping them would reject inputs that work today;
# documenting them would widen the public contract inside a drift fix. Pinned
# here so a FIFTH undocumented name has to be a decision rather than a leak.
PATTERN_DECLARED_ALIASES = {"conversation", "email", "image_alt_text", "log"}


class WireError(AssertionError):
    """The server's replies are not valid successful JSON-RPC responses."""


def parse_replies(stdout):
    """Replies by id, each VALIDATED as a successful JSON-RPC response.

    ASTRA, round 1 on 95b5e69: the first version of this helper returned the
    reply objects and let the assertions read `result`, so a reply carrying a
    top-level `error` ALONGSIDE a result was accepted as successful
    introspection. Three such wires -- error+result on scanner_info, on
    tools/list, and on both -- left all three tests PASS. The `isError is False`
    check below only ever inspected the nested MCP tool payload, which is a
    different layer.

    A malformed server is not a passing server, so this refuses here rather
    than letting the vocabulary assertions speak about a wire that never
    answered properly.
    """
    replies = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            replies.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise WireError(f"server emitted a line that is not JSON: {e}")
    if not replies:
        raise WireError("server returned nothing")
    by_id = {}
    for r in replies:
        if "id" not in r:
            continue                      # notifications carry no id
        if "error" in r:
            raise WireError(f"reply id={r['id']} carries a JSON-RPC error: {r['error']!r}")
        if "result" not in r:
            raise WireError(f"reply id={r['id']} has neither result nor error")
        by_id[r["id"]] = r
    return by_id


def _channel_list(value, where):
    """A channel vocabulary is an ARRAY OF STRINGS or it is not a vocabulary.

    ASTRA's other wire finding: a dict in place of the array passed both
    comparisons, because `set()` of a dict silently yields its keys and the
    type is discarded.
    """
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise WireError(f"{where} is not an array of strings: {type(value).__name__} {value!r}")
    return set(value)


def _ask_server(messages, timeout=180):
    """Drive a real `python -m sunglasses.mcp` over stdio and return its replies."""
    proc = subprocess.run(
        [sys.executable, "-m", "sunglasses.mcp"],
        input="".join(json.dumps(m) + "\n" for m in messages),
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=timeout,
    )
    assert "Traceback (most recent call last)" not in proc.stdout + proc.stderr, (
        f"traceback over the wire:\nstdout={proc.stdout[:600]}\nstderr={proc.stderr[:600]}")
    return parse_replies(proc.stdout)


@pytest.fixture(scope="module")
def surfaces():
    """Both published channel lists, as a client receives them."""
    replies = _ask_server([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "channel-truth-test", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "scanner_info", "arguments": {}}},
    ])
    assert 2 in replies and 3 in replies, (
        f"the server did not answer both introspection requests: ids {sorted(replies)}")

    tools = {t["name"]: t for t in replies[2]["result"]["tools"]}
    enum = _channel_list(
        tools["scan_text"]["inputSchema"]["properties"]["channel"]["enum"],
        "scan_text inputSchema enum")

    payload = replies[3]["result"]
    assert payload.get("isError") is False, f"scanner_info returned an error: {payload}"
    info = json.loads(payload["content"][0]["text"])
    channels = _channel_list(info["channels"], "scanner_info channels")

    assert enum and channels, "a published vocabulary that is empty is not a vocabulary"
    return {"enum": enum, "info": channels}


def test_the_two_published_surfaces_agree(surfaces):
    """scan_text's enum and scanner_info's channels are one set, or neither is true."""
    assert surfaces["enum"] == surfaces["info"], (
        "the running server publishes two different channel vocabularies.\n"
        f"  scan_text inputSchema enum : {sorted(surfaces['enum'])}\n"
        f"  scanner_info channels      : {sorted(surfaces['info'])}\n"
        f"  only in the enum           : {sorted(surfaces['enum'] - surfaces['info'])}\n"
        f"  only in scanner_info       : {sorted(surfaces['info'] - surfaces['enum'])}")


def test_what_is_published_is_the_documented_contract(surfaces):
    """Agreeing on the WRONG set would still be agreement, so anchor it."""
    documented = set(SunglassesEngine.DOCUMENTED_CHANNELS)
    assert surfaces["info"] == documented, (
        f"scanner_info publishes {sorted(surfaces['info'])}, "
        f"DOCUMENTED_CHANNELS is {sorted(documented)}")
    assert surfaces["enum"] == documented, (
        f"scan_text's enum publishes {sorted(surfaces['enum'])}, "
        f"DOCUMENTED_CHANNELS is {sorted(documented)}")


def test_valid_channels_is_the_contract_plus_exactly_the_named_aliases():
    """A fifth undocumented-but-reachable channel must be a decision, not a leak."""
    engine = SunglassesEngine()
    expected = set(engine.DOCUMENTED_CHANNELS) | PATTERN_DECLARED_ALIASES
    actual = set(engine.valid_channels)
    assert actual == expected, (
        "the accepted channel vocabulary moved.\n"
        f"  new and undocumented : {sorted(actual - expected)}\n"
        f"  expected but gone    : {sorted(expected - actual)}\n"
        "Adding a channel to a pattern widens what the engine accepts. Document "
        "it in DOCUMENTED_CHANNELS, or name it in PATTERN_DECLARED_ALIASES with "
        "a reason.")


# ── REJECTION CONTROLS ────────────────────────────────────────────────────────
# The wire shapes ASTRA used to make the two assertions above falsely green.
# These drive `parse_replies` / `_channel_list` directly rather than a
# subprocess: the defect was never in the server, it was in what this file
# accepted from one, and a control that has to boot a server to say so is a
# slower control that proves the same thing.

_GOOD_LIST = json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}})
_GOOD_INFO = json.dumps({"jsonrpc": "2.0", "id": 3, "result": {"content": []}})


@pytest.mark.parametrize("name,wire", [
    ("error alongside result on scanner_info",
     [_GOOD_LIST, json.dumps({"jsonrpc": "2.0", "id": 3, "result": {"content": []},
                              "error": {"code": -32603, "message": "boom"}})]),
    ("error alongside result on tools/list",
     [json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": []},
                  "error": {"code": -32603, "message": "boom"}}), _GOOD_INFO]),
    ("error alongside result on both",
     [json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": []},
                  "error": {"code": -1, "message": "x"}}),
      json.dumps({"jsonrpc": "2.0", "id": 3, "result": {"content": []},
                  "error": {"code": -1, "message": "x"}})]),
    ("reply with neither result nor error",
     [json.dumps({"jsonrpc": "2.0", "id": 2}), _GOOD_INFO]),
    ("a line that is not JSON", ["{not json", _GOOD_INFO]),
    ("no replies at all", []),
])
def test_a_malformed_wire_is_refused_not_read(name, wire):
    """Each of these left all three vocabulary assertions PASS before the fix."""
    with pytest.raises(WireError):
        parse_replies("\n".join(wire))


@pytest.mark.parametrize("bad", [
    {"message": 1, "file": 2},          # a dict: set() takes its keys, type discarded
    "message,file",                     # a string: set() takes its characters
    ["message", 7],                     # a list with a non-string member
    None,
])
def test_a_channel_vocabulary_must_be_an_array_of_strings(bad):
    with pytest.raises(WireError):
        _channel_list(bad, "control")


def test_the_controls_accept_a_well_formed_wire():
    """Otherwise the two controls above pass by refusing everything."""
    ok = parse_replies("\n".join([_GOOD_LIST, _GOOD_INFO]))
    assert set(ok) == {2, 3}
    assert _channel_list(["message", "file"], "control") == {"message", "file"}
