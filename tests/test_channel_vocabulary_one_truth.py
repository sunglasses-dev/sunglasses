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
        if not isinstance(r, dict):
            raise WireError(f"a reply is not a JSON object: {type(r).__name__}")
        # ROUND 2: the envelope was never checked. Removing `jsonrpc` entirely,
        # or setting it to "1.0", left both vocabulary assertions green -- this
        # helper claimed to validate a successful JSON-RPC response and did not
        # look at the one field that says which protocol it is.
        if r.get("jsonrpc") != "2.0":
            raise WireError(f"reply is not JSON-RPC 2.0: jsonrpc={r.get('jsonrpc')!r}")
        if "id" not in r:
            continue                      # notifications carry no id
        if "error" in r:
            raise WireError(f"reply id={r['id']} carries a JSON-RPC error: {r['error']!r}")
        if "result" not in r:
            raise WireError(f"reply id={r['id']} has neither result nor error")
        # ROUND 2: this was `by_id[r["id"]] = r`, so a second answer to the same
        # request SILENTLY OVERWROTE the first and the verdict depended on which
        # conflicting answer happened to survive dictionary insertion. A
        # null-result answer followed by a good one passed; the same pair in the
        # other order rejected. One request gets one answer.
        if r["id"] in by_id:
            raise WireError(f"the server answered id={r['id']} more than once; "
                            "a request with two answers has no answer")
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


def _schema_enum(prop, where):
    """The enum of a JSON-Schema property that actually describes strings.

    ROUND 2: only the enum was read. Changing the property's `type` to
    "integer" left both vocabulary assertions green over the same nine STRINGS
    -- the test asserted a published vocabulary the schema permits none of.

    Extracted into its own helper because the first version of this repair lived
    inline in the fixture, where the only thing that could exercise it was a live
    server, so removing it reddened NOTHING. A check no control can reach is not
    a check; that was caught by mutating each repair in turn, not by reading.
    """
    if not isinstance(prop, dict):
        raise WireError(f"{where}: channel property is not an object")
    if prop.get("type") != "string":
        raise WireError(f"{where}: channel property does not describe strings: "
                        f"type={prop.get('type')!r}")
    if "enum" not in prop:
        raise WireError(f"{where}: channel property has no enum")
    return _channel_list(prop["enum"], f"{where} enum")


def _text_result(payload, where):
    """The decoded JSON of an MCP tool result's TEXT block.

    ROUND 2, two findings in one place. `payload["content"][0]["text"]` read any
    block carrying a `text` key as text content: deleting the block's `type`, or
    setting it to "image" with no image fields, left both vocabulary assertions
    green over a malformed MCP result.

    And `payload.get("isError") is False` was a FALSE KILL -- ASTRA's only one.
    MCP defines isError as OPTIONAL with absence meaning success, so a
    protocol-correct server that omits it was rejected. Absence or literal False
    is success; True or any other value is not.
    """
    if not isinstance(payload, dict):
        raise WireError(f"{where}: result is not an object: {type(payload).__name__}")
    flag = payload.get("isError", False)
    if flag is not False:
        raise WireError(f"{where}: isError={flag!r}; success is absence or literal false")
    content = payload.get("content")
    if not isinstance(content, list):
        raise WireError(f"{where}: content is not an array: {type(content).__name__}")
    texts = [b for b in content
             if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)]
    if not texts:
        raise WireError(f"{where}: no well-formed text block in {len(content)} content block(s)")
    try:
        return json.loads(texts[0]["text"])
    except json.JSONDecodeError as e:
        raise WireError(f"{where}: text block is not JSON: {e}")


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
    enum = _schema_enum(tools["scan_text"]["inputSchema"]["properties"]["channel"],
                        "scan_text inputSchema")

    channels = _channel_list(_text_result(replies[3]["result"], "scanner_info")["channels"],
                             "scanner_info channels")

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


# ── ROUND 3 CONTROLS: the seven wires that still slipped through round 2 ──────
# ASTRA drove 24 wires against the round-2 fixture; 7 defective ones passed BOTH
# vocabulary assertions. Each is a row here, and the two rows at the end are the
# false-kill guard: a protocol-correct server must still be accepted.

def _env(i, result):
    return json.dumps({"jsonrpc": "2.0", "id": i, "result": result})


@pytest.mark.parametrize("name,wire", [
    # one request, two answers -- the verdict used to depend on insertion order
    ("the same id answered twice", [_env(2, {"tools": []}), _env(2, {"tools": []})]),
    ("a null answer overwritten by a good one",
     [_env(2, None), _env(2, {"tools": []})]),
    # the envelope this helper claims to validate
    ("no jsonrpc field at all",
     [json.dumps({"id": 2, "result": {"tools": []}}), _env(3, {"content": []})]),
    ("jsonrpc 1.0",
     [json.dumps({"jsonrpc": "1.0", "id": 2, "result": {"tools": []}}), _env(3, {"content": []})]),
    ("a reply that is not an object", [json.dumps(["not", "an", "object"])]),
])
def test_round3_envelope_wires_are_refused(name, wire):
    with pytest.raises(WireError):
        parse_replies("\n".join(wire))


@pytest.mark.parametrize("name,payload", [
    ("a content block with no type",
     {"content": [{"text": '{"channels": ["message"]}'}], "isError": False}),
    ("a content block typed image",
     {"content": [{"type": "image", "text": '{"channels": ["message"]}'}], "isError": False}),
    ("content that is an object, not an array",
     {"content": {"type": "text", "text": "{}"}, "isError": False}),
    ("a text block that is not JSON",
     {"content": [{"type": "text", "text": "not json at all"}], "isError": False}),
    ("isError true", {"content": [{"type": "text", "text": "{}"}], "isError": True}),
    ("isError a non-bool", {"content": [{"type": "text", "text": "{}"}], "isError": "no"}),
])
def test_round3_malformed_tool_results_are_refused(name, payload):
    with pytest.raises(WireError):
        _text_result(payload, "control")


def test_a_result_omitting_the_optional_isError_is_ACCEPTED():
    """ASTRA's one false kill, inherited from round 1 and fixed in round 3.

    MCP defines isError as optional, absence meaning success. The round-1 check
    `payload.get("isError") is False` REQUIRED it, so a protocol-correct server
    that omitted it was rejected. Rejecting a correct server teaches everyone to
    ignore the gate, which is the same damage as passing a broken one.
    """
    got = _text_result({"content": [{"type": "text", "text": '{"channels": ["message"]}'}]},
                       "control")
    assert got == {"channels": ["message"]}


def test_a_well_formed_text_result_is_accepted():
    got = _text_result({"content": [{"type": "text", "text": '{"channels": ["file"]}'}],
                        "isError": False}, "control")
    assert got == {"channels": ["file"]}


@pytest.mark.parametrize("name,prop", [
    ("type integer over nine string names",
     {"type": "integer", "enum": ["message", "file"]}),
    ("no type at all", {"enum": ["message", "file"]}),
    ("type array", {"type": "array", "enum": ["message", "file"]}),
    ("a schema with no enum", {"type": "string"}),
    ("not an object at all", ["message", "file"]),
])
def test_round3_a_schema_that_permits_none_of_its_enum_is_refused(name, prop):
    with pytest.raises(WireError):
        _schema_enum(prop, "control")


def test_a_well_formed_channel_schema_is_accepted():
    assert _schema_enum({"type": "string", "enum": ["message", "file"]},
                        "control") == {"message", "file"}
