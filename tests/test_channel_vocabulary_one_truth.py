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


# ── THE READER IS AN ALLOWLIST ────────────────────────────────────────────────
# Rounds 1, 2 and 3 all failed the same way. Each round named the defective wire
# shapes the reviewer had found and refused those; each round the reviewer came
# back with shapes nobody had named. Round 3's count was 8 more. A denylist of
# wire defects is a list of the defects we have already met, so the next round's
# score is decided by the reviewer's imagination rather than by this file.
#
# So round 4 inverts it. Below is the ONE shape this server is allowed to answer
# in, stated positively and key by key. Anything else is refused BY
# CONSTRUCTION -- including shapes neither of us has thought of, which is the
# only part that generalises. Every key in every object is either REQUIRED,
# explicitly OPTIONAL, or a refusal; there is no "and whatever else is there".
#
# That rule is borrowed on purpose. It is the same fail-closed-on-an-
# unclassified-key rule that the worker's pattern field contract needed, for the
# same reason: a reader that only rejects what it recognises is a reader that
# passes what it does not.
#
# The cost of an allowlist is false kills, and round 3 produced two real ones
# (a channel schema with no `type`, and one with `type: ["string"]`, both valid
# JSON Schema permitting exactly the nine advertised names). So each allowlist
# below is accompanied by acceptance controls, not only rejection controls, and
# the accepted set is stated in terms of what the protocol permits rather than
# what this server happens to emit today.


def _only_keys(obj, where, required=(), optional=()):
    """`obj` is an object whose keys are exactly `required` plus any `optional`.

    The primitive the rest of this file is built from. An unexpected key is a
    refusal rather than something to ignore, which is what turns each reader
    below from a denylist into an allowlist.
    """
    if not isinstance(obj, dict):
        raise WireError(f"{where}: expected an object, got {type(obj).__name__}")
    missing = [k for k in required if k not in obj]
    if missing:
        raise WireError(f"{where}: missing required key(s) {missing}")
    unknown = sorted(set(obj) - set(required) - set(optional))
    if unknown:
        raise WireError(
            f"{where}: unexpected key(s) {unknown}. This reader accepts one shape and "
            f"refuses the rest by construction; if {unknown} is legitimate, add it to "
            f"the allowlist with a reason and a control.")
    return obj


def _rpc_id(value, where):
    """The id of a reply, as an int, or a refusal.

    ASTRA round 3: `id` was never examined, so an initialize reply carrying
    `true` or `1.5` correlated to request 1 in a plain dict. JSON-RPC ids are a
    number or a string; `True` is neither (Python's isinstance(True, int) is the
    trap), and 1.5 is a different number from the 1 we sent. 1.0 IS the number 1
    -- JSON does not distinguish them -- so it is accepted, and there is a
    control for that so this does not become a third false kill.

    We send integer ids, so a correlated reply carries that same integer. A
    string "2" is a well-formed JSON-RPC id and still is not the id of the
    request we made.
    """
    if isinstance(value, bool):
        raise WireError(f"{where}: id={value!r} is a boolean, not a JSON-RPC id")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not value.is_integer():
            raise WireError(f"{where}: id={value!r} is not the integer id this client sent")
        return int(value)
    raise WireError(
        f"{where}: id={value!r} ({type(value).__name__}) is not one of the integer ids "
        f"this client sent; a reply that does not echo the request id answers nothing")


def parse_replies(stdout):
    """Replies by id, each a successful JSON-RPC response of the ONE shape below.

    A successful response is exactly `{jsonrpc, id, result}`. Not a superset.

    ROUND 1: this returned the raw objects, so `error` ALONGSIDE `result` read
    as successful introspection -- three such wires left every assertion green.
    ROUND 2: the envelope was never checked at all; removing `jsonrpc`, or
    setting it to "1.0", stayed green, and a second answer to one id silently
    overwrote the first, so the verdict depended on dict insertion order.
    ROUND 3: the ids themselves were never read.

    Each of those was repaired by naming the shape that had just been found.
    Here the accepted shape is named instead, and `error`, a missing `result`, a
    stray key and a malformed id are all refused by the same rule rather than by
    four separate checks.
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
    for i, r in enumerate(replies):
        where = f"reply {i}"
        if not isinstance(r, dict):
            raise WireError(f"{where} is not a JSON object: {type(r).__name__}")
        # A notification is the one other legal thing on this stream. It carries
        # no id and nothing here reads it, so it is skipped -- but it must still
        # be a notification and not a response missing its id.
        if "id" not in r:
            _only_keys(r, f"{where} (notification)",
                       required=("jsonrpc", "method"), optional=("params",))
            if r["jsonrpc"] != "2.0":
                raise WireError(f"{where}: jsonrpc={r['jsonrpc']!r}, not the string '2.0'")
            continue
        _only_keys(r, where, required=("jsonrpc", "id", "result"))
        if r["jsonrpc"] != "2.0":
            raise WireError(f"{where}: jsonrpc={r['jsonrpc']!r}, not the string '2.0'")
        rid = _rpc_id(r["id"], where)
        if not isinstance(r["result"], dict):
            raise WireError(f"{where}: result is not an object: {type(r['result']).__name__}")
        if rid in by_id:
            raise WireError(f"the server answered id={rid} more than once; "
                            "a request with two answers has no answer")
        by_id[rid] = r
    return by_id


def _channel_list(value, where):
    """A channel vocabulary is an ARRAY OF STRINGS or it is not a vocabulary.

    ASTRA round 1: a dict in place of the array passed both comparisons, because
    `set()` of a dict silently yields its keys and the type is discarded.
    """
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise WireError(f"{where} is not an array of strings: {type(value).__name__} {value!r}")
    if len(set(value)) != len(value):
        dupes = sorted({v for v in value if value.count(v) > 1})
        raise WireError(f"{where} publishes {dupes} more than once")
    return set(value)


# A JSON-Schema keyword that only annotates. None of these can narrow the set of
# values a schema permits, so a channel property may carry them and this reader
# ignores them. Anything NOT in this set and not in the two constraining
# keywords below is refused -- which is what makes `const`, `not`, `maxLength`,
# `pattern`, `allOf`, `$ref` and every keyword invented after today a refusal
# without this file having heard of them.
_SCHEMA_ANNOTATIONS = frozenset({
    "description", "title", "default", "examples", "$comment", "deprecated",
    "readOnly", "writeOnly",
})


def _channel_enum(prop, where):
    """The advertised channel names, from a property schema that PUBLISHES A LIST.

    ROUND 2: only `enum` was read, so a property typed "integer" over nine
    strings left both assertions green on a schema permitting none of them.
    ROUND 3's repair required `type == "string"` literally, which fixed that and
    created two false kills: `{"enum": [...]}` with no `type`, and
    `{"type": ["string"], "enum": [...]}`, are both valid JSON Schema permitting
    exactly the nine names. Round 3 also found three MORE shapes that keep
    `type: "string"` and still permit nothing -- `const`, `not`, `maxLength`.

    Denylisting those three would have been round 4 of the same mistake, so:
    the only keywords allowed to CONSTRAIN this property are `type` and `enum`.
    A schema carrying any other constraining keyword is refused without this
    reader knowing what that keyword means, which is the point -- `const`,
    `not` and `maxLength` are refused by the same rule that refuses whatever the
    next reviewer brings.
    """
    _only_keys(prop, f"{where}: channel property",
               required=("enum",), optional=("type",) + tuple(_SCHEMA_ANNOTATIONS))
    if "type" in prop and prop["type"] not in ("string", ["string"]):
        raise WireError(
            f"{where}: channel property does not describe strings: type={prop['type']!r}. "
            f"Accepted: \"string\", [\"string\"], or no type at all (the enum alone "
            f"restricts the value).")
    names = _channel_list(prop["enum"], f"{where} enum")
    if not names:
        raise WireError(f"{where}: an empty enum advertises no channels")
    if "default" in prop and prop["default"] not in names:
        raise WireError(f"{where}: default={prop['default']!r} is not one of the "
                        f"{len(names)} names the enum advertises")
    return names


def _one_tool(tools, name, where):
    """The single descriptor for `name`, or a refusal.

    ROUND 3: the fixture built `{t["name"]: t for t in tools}`, so two
    `scan_text` descriptors with different enums resolved to whichever came
    last -- the same overwrite defect as the duplicate reply id, one layer down.
    Two definitions of one tool are not a published vocabulary; they are a
    server that has not decided.
    """
    if not isinstance(tools, list):
        raise WireError(f"{where}: tools is not an array: {type(tools).__name__}")
    matches = [t for t in tools if isinstance(t, dict) and t.get("name") == name]
    if not matches:
        raise WireError(f"{where}: no tool named {name!r} in "
                        f"{[t.get('name') if isinstance(t, dict) else t for t in tools]}")
    if len(matches) > 1:
        raise WireError(f"{where}: {len(matches)} tools named {name!r}; a tool defined "
                        f"twice has no definition")
    return matches[0]


def _tool_result_json(payload, where):
    """The decoded JSON a tool result publishes, from content blocks that all parse.

    ROUND 2: `content[0]["text"]` read any block with a `text` key as text, so a
    block with no `type`, or typed "image", was read as the payload; and
    `isError is False` false-killed a protocol-correct server that omits the
    optional field.
    ROUND 3: the comprehension that replaced it silently DISCARDED malformed
    blocks, so `{"type": "image", "text": "{}"}` -- an image block with no image
    in it -- rode along unnoticed; and where two text blocks published different
    channel lists, the first one won and the contradiction was reported as
    agreement.

    MCP permits several content blocks, so rejecting multiplicity would be a
    false kill (there are acceptance controls for an image before the text, and
    for a repeated identical text). What is refused is a block this reader
    cannot fully account for, and a set of text blocks that do not say the same
    thing.

    ROUND 4 accepted `structuredContent` and did not read it, and disclosed that
    as out of scope. It is not out of scope. `structuredContent` is the SAME
    result in structured form and a client may read it INSTEAD of the text, so a
    server whose structuredContent says five channels while its text says nine
    is publishing two vocabularies -- which is the defect this entire file
    exists to catch, arriving one layer below where it was being looked for.
    Round 4 would have reported that as agreement. Found by the reviewer's own
    round-4 disclosure, run through the candidate-shape probe.
    """
    _only_keys(payload, where, required=("content",),
               optional=("isError", "structuredContent", "_meta"))
    flag = payload.get("isError", False)
    if flag is not False:
        raise WireError(f"{where}: isError={flag!r}; success is absence or literal false")

    content = payload["content"]
    if not isinstance(content, list):
        raise WireError(f"{where}: content is not an array: {type(content).__name__}")
    if not content:
        raise WireError(f"{where}: content is empty; a result publishing nothing "
                        "publishes no vocabulary")

    texts = []
    for i, block in enumerate(content):
        bw = f"{where} content[{i}]"
        if not isinstance(block, dict):
            raise WireError(f"{bw} is not an object: {type(block).__name__}")
        btype = block.get("type")
        if not isinstance(btype, str):
            raise WireError(f"{bw}: type={btype!r} is not a string")
        # Every block is checked against the shape its own type promises. A
        # block that does not carry what its type requires -- or that carries a
        # field from a different type -- is refused rather than skipped, because
        # skipping is how an image block carrying `text` went unnoticed.
        if btype == "text":
            _only_keys(block, f"{bw} (text)", required=("type", "text"),
                       optional=("annotations", "_meta"))
            if not isinstance(block["text"], str):
                raise WireError(f"{bw}: text is {type(block['text']).__name__}, not a string")
            texts.append((i, block["text"]))
        elif btype in ("image", "audio"):
            _only_keys(block, f"{bw} ({btype})", required=("type", "data", "mimeType"),
                       optional=("annotations", "_meta"))
        elif btype == "resource":
            _only_keys(block, f"{bw} (resource)", required=("type", "resource"),
                       optional=("annotations", "_meta"))
        else:
            raise WireError(f"{bw}: content block type {btype!r} is not one this reader "
                            f"accounts for")

    if not texts:
        raise WireError(f"{where}: no text block in {len(content)} content block(s)")

    decoded = []
    for i, raw in texts:
        try:
            decoded.append((i, json.loads(raw)))
        except json.JSONDecodeError as e:
            raise WireError(f"{where} content[{i}]: text block is not JSON: {e}")
    first_i, first = decoded[0]
    for i, other in decoded[1:]:
        if other != first:
            raise WireError(
                f"{where}: content[{first_i}] and content[{i}] publish DIFFERENT bodies. "
                f"Reporting either one as the server's answer would report a "
                f"disagreement as agreement.")

    # The same rule, one layer down. Present and equal is fine; present and
    # different is two vocabularies from one server.
    if "structuredContent" in payload and payload["structuredContent"] != first:
        raise WireError(
            f"{where}: structuredContent and the text block publish DIFFERENT bodies. "
            f"A client may read either one, so a server that disagrees with itself here "
            f"has published two answers and this reader will not pick one.")
    return first


def _ask_server(messages, timeout=180):
    """Drive a real `python -m sunglasses.mcp` over stdio and return its raw stdout."""
    proc = subprocess.run(
        [sys.executable, "-m", "sunglasses.mcp"],
        input="".join(json.dumps(m) + "\n" for m in messages),
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=timeout,
    )
    assert "Traceback (most recent call last)" not in proc.stdout + proc.stderr, (
        f"traceback over the wire:\nstdout={proc.stdout[:600]}\nstderr={proc.stderr[:600]}")
    # Returns RAW STDOUT. Reading it is read_surfaces' job, so that the real
    # server and a saved defective wire go through the same code.
    return proc.stdout


def read_surfaces(stdout):
    """Both published channel vocabularies, read from one server's stdout.

    THE WHOLE READING PATH IS THIS ONE FUNCTION, and it exists because of
    ASTRA's round-3 finding: every helper below was unit-tested, and swapping
    the FIXTURE's single call to the schema reader for a raw enum read left
    33/33 green while a known-defective wire went back to passing. The repairs
    were proven; their presence in the path that actually runs was not.

    A helper control proves a helper. Only a control that drives the same
    function the fixture drives can prove the fixture uses it. So the fixture no
    longer reads anything itself -- it supplies stdout from a real server, and
    the defective-wire controls supply stdout from a file. One path, two
    sources, and cutting any call in it reddens a named row.
    """
    replies = parse_replies(stdout)
    if 2 not in replies or 3 not in replies:
        raise WireError(
            f"the server did not answer both introspection requests: ids {sorted(replies)}")

    scan_text = _one_tool(replies[2]["result"]["tools"], "scan_text", "tools/list")
    enum = _channel_enum(scan_text["inputSchema"]["properties"]["channel"],
                         "scan_text inputSchema")

    info = _tool_result_json(replies[3]["result"], "scanner_info")
    if not isinstance(info, dict):
        raise WireError(f"scanner_info published a {type(info).__name__}, not an object")
    if "channels" not in info:
        raise WireError("scanner_info published no `channels` key")
    channels = _channel_list(info["channels"], "scanner_info channels")

    if not enum or not channels:
        raise WireError("a published vocabulary that is empty is not a vocabulary")
    return {"enum": enum, "info": channels}


@pytest.fixture(scope="module")
def surfaces():
    """Both published channel lists, as a client receives them from the real server."""
    return read_surfaces(_ask_server([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "channel-truth-test", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "scanner_info", "arguments": {}}},
    ]))


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


# ── ROUND 4 CONTROLS ─────────────────────────────────────────────────────────
# Every wire shape any round found, as a row, in both directions.
#
# Rounds 1-3 each added rejection rows for the shapes just found, and each time
# the next round brought shapes nobody had listed. The reader is now an
# allowlist, so these rows have a different job: they are no longer the
# definition of what is refused -- the allowlist is -- they are evidence that it
# refuses what it should AND, just as importantly, that it still accepts a
# protocol-correct server. Round 3 produced two false kills; an allowlist
# written without acceptance rows produces more.
#
# The last row of the schema block is deliberately a keyword nobody has ever
# sent us. It is the only row here that tests the generalisation rather than a
# past finding: if it ever goes green, the reader has quietly become a denylist
# again.

def _env(i, result):
    return json.dumps({"jsonrpc": "2.0", "id": i, "result": result})


_ENV_2 = _env(2, {"tools": []})
_ENV_3 = _env(3, {"content": [{"type": "text", "text": "{}"}]})


@pytest.mark.parametrize("name,wire", [
    # -- one request, one answer (round 2) -------------------------------------
    ("the same id answered twice", [_ENV_2, _ENV_2]),
    ("a null answer overwritten by a good one", [_env(2, None), _ENV_2]),
    # -- the envelope itself (round 2) -----------------------------------------
    ("no jsonrpc field at all", [json.dumps({"id": 2, "result": {"tools": []}}), _ENV_3]),
    ("jsonrpc 1.0", [json.dumps({"jsonrpc": "1.0", "id": 2, "result": {"tools": []}}), _ENV_3]),
    ("jsonrpc as the number 2.0",
     [json.dumps({"jsonrpc": 2.0, "id": 2, "result": {"tools": []}}), _ENV_3]),
    ("jsonrpc null", [json.dumps({"jsonrpc": None, "id": 2, "result": {"tools": []}}), _ENV_3]),
    ("jsonrpc an array", [json.dumps({"jsonrpc": ["2.0"], "id": 2, "result": {}}), _ENV_3]),
    ("a reply that is not an object", [json.dumps(["not", "an", "object"])]),
    # -- result and error (round 1) --------------------------------------------
    ("error alongside result",
     [json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": []},
                  "error": {"code": -32603, "message": "boom"}}), _ENV_3]),
    ("neither result nor error", [json.dumps({"jsonrpc": "2.0", "id": 2}), _ENV_3]),
    ("result is null", [_env(2, None), _ENV_3]),
    ("result is an array", [_env(2, []), _ENV_3]),
    ("result is a string", [_env(2, "tools"), _ENV_3]),
    # -- the ids (round 3) ------------------------------------------------------
    ("an id of boolean true",
     [json.dumps({"jsonrpc": "2.0", "id": True, "result": {"tools": []}}), _ENV_3]),
    ("a fractional id",
     [json.dumps({"jsonrpc": "2.0", "id": 1.5, "result": {}}), _ENV_2, _ENV_3]),
    ("a string id where an integer was sent",
     [json.dumps({"jsonrpc": "2.0", "id": "2", "result": {"tools": []}}), _ENV_3]),
    # -- the allowlist generalising past any named finding ----------------------
    ("a successful response carrying an extra top-level key",
     [json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}, "hint": "trust me"}),
      _ENV_3]),
    # -- the parser floor (round 1) --------------------------------------------
    ("a line that is not JSON", ["{not json", _ENV_3]),
    ("no replies at all", []),
])
def test_a_reply_outside_the_one_accepted_envelope_is_refused(name, wire):
    with pytest.raises(WireError):
        parse_replies("\n".join(wire))


@pytest.mark.parametrize("name,wire", [
    ("the canonical envelope", [_ENV_2, _ENV_3]),
    # JSON does not distinguish 2 from 2.0, so a server emitting the integral
    # float has echoed our id. Refusing it would be a third false kill.
    ("integral float ids",
     [json.dumps({"jsonrpc": "2.0", "id": 2.0, "result": {"tools": []}}),
      json.dumps({"jsonrpc": "2.0", "id": 3.0,
                  "result": {"content": [{"type": "text", "text": "{}"}]}})]),
    ("a notification sharing the stream",
     [json.dumps({"jsonrpc": "2.0", "method": "notifications/progress",
                  "params": {"n": 1}}), _ENV_2, _ENV_3]),
])
def test_a_protocol_correct_wire_is_accepted(name, wire):
    """Otherwise every rejection row above passes by refusing everything."""
    got = parse_replies("\n".join(wire))
    assert set(got) == {2, 3}


# ── the channel property schema ──────────────────────────────────────────────

@pytest.mark.parametrize("name,prop", [
    # round 2: the enum was read without its surrounding type
    ("type integer over string names", {"type": "integer", "enum": ["message", "file"]}),
    ("type array", {"type": "array", "enum": ["message", "file"]}),
    ("type a union including null", {"type": ["string", "null"], "enum": ["message"]}),
    ("no enum at all", {"type": "string"}),
    ("not an object at all", ["message", "file"]),
    ("an empty enum", {"type": "string", "enum": []}),
    ("an enum that is not strings", {"type": "string", "enum": ["message", 7]}),
    ("a channel advertised twice", {"type": "string", "enum": ["message", "message"]}),
    # round 3: three MORE ways to keep `type: string` and permit none of the enum
    ("const excluding the enum",
     {"type": "string", "enum": ["message", "file"], "const": "nothing"}),
    ("not excluding the enum",
     {"type": "string", "enum": ["message", "file"], "not": {"type": "string"}}),
    ("maxLength excluding the enum",
     {"type": "string", "enum": ["message", "file"], "maxLength": 1}),
    ("a default that is not one of the advertised names",
     {"type": "string", "enum": ["message", "file"], "default": "elsewhere"}),
    # THE GENERALISATION ROW. `pattern` was never reported by any round; it is
    # refused because it is not on the allowlist, not because anyone met it.
    ("a constraining keyword no round has ever sent",
     {"type": "string", "enum": ["message", "file"], "pattern": "^zzz$"}),
])
def test_a_channel_schema_outside_the_one_accepted_shape_is_refused(name, prop):
    with pytest.raises(WireError):
        _channel_enum(prop, "control")


@pytest.mark.parametrize("name,prop", [
    ("type string with an enum", {"type": "string", "enum": ["message", "file"]}),
    # ASTRA round 3, false kill 1: an enum of strings with no `type` is valid
    # JSON Schema and permits exactly those strings.
    ("no type at all, the enum alone", {"enum": ["message", "file"]}),
    # ASTRA round 3, false kill 2: the singleton type array is the same type.
    ("the singleton type array", {"type": ["string"], "enum": ["message", "file"]}),
    ("annotations that constrain nothing",
     {"type": "string", "enum": ["message", "file"], "description": "which channel",
      "title": "channel", "default": "message"}),
])
def test_a_valid_channel_schema_is_accepted(name, prop):
    """The two rows in the middle are the false kills round 3's repair created."""
    assert _channel_enum(prop, "control") == {"message", "file"}


def test_the_schema_reader_accepts_what_this_server_actually_publishes():
    """A control that uses the real shape, so the allowlist cannot drift off it.

    Every row above is a shape someone wrote by hand. This one is the property
    the running server emits today; if the allowlist ever stops accepting it,
    that is a false kill against our own product and this test says so before a
    reviewer does.
    """
    prop = {
        "type": "string",
        "description": "The input channel type. Affects which patterns are checked. "
                       "Unknown channels are rejected (fail closed).",
        "enum": list(SunglassesEngine.DOCUMENTED_CHANNELS),
        "default": "message",
    }
    assert _channel_enum(prop, "control") == set(SunglassesEngine.DOCUMENTED_CHANNELS)


# ── the tool result ──────────────────────────────────────────────────────────

_TEXT_A = {"type": "text", "text": '{"channels": ["message"]}'}
_TEXT_B = {"type": "text", "text": '{"channels": ["file"]}'}


@pytest.mark.parametrize("name,payload", [
    # round 2
    ("a content block with no type", {"content": [{"text": '{"channels": []}'}]}),
    ("content that is an object, not an array", {"content": {"type": "text", "text": "{}"}}),
    ("a text block that is not JSON", {"content": [{"type": "text", "text": "not json"}]}),
    ("isError true", {"content": [_TEXT_A], "isError": True}),
    ("isError a non-bool", {"content": [_TEXT_A], "isError": "no"}),
    # round 3: the comprehension DISCARDED what it could not read
    ("an image block carrying text and no image",
     {"content": [{"type": "image", "text": "{}"}, _TEXT_A]}),
    ("two text blocks publishing different payloads", {"content": [_TEXT_A, _TEXT_B]}),
    ("the same two in the other order", {"content": [_TEXT_B, _TEXT_A]}),
    # the allowlist generalising
    ("a content block of a type nobody has sent",
     {"content": [{"type": "video", "data": "x"}, _TEXT_A]}),
    ("a text block carrying an extra key",
     {"content": [{"type": "text", "text": "{}", "trust_me": True}]}),
    ("a result carrying an extra top-level key",
     {"content": [_TEXT_A], "shortcut": "yes"}),
    # round 4 accepted this and called it out of scope; it is the same defect
    # one layer down -- a client may read structuredContent instead of the text
    ("structuredContent contradicting the text block",
     {"content": [_TEXT_A], "structuredContent": {"channels": ["file"]}}),
    ("structuredContent contradicting it by omission",
     {"content": [_TEXT_A], "structuredContent": {}}),
    ("no content blocks at all", {"content": []}),
    ("no text block among the content", {"content": [{"type": "image", "data": "a",
                                                      "mimeType": "image/png"}]}),
])
def test_a_tool_result_outside_the_one_accepted_shape_is_refused(name, payload):
    with pytest.raises(WireError):
        _tool_result_json(payload, "control")


@pytest.mark.parametrize("name,payload,expected", [
    ("the canonical result", {"content": [_TEXT_A], "isError": False}, ["message"]),
    # MCP defines isError as optional, absence meaning success. Requiring it was
    # round 1's false kill; rejecting a correct server teaches everyone to
    # ignore the gate, which is the same damage as passing a broken one.
    ("isError omitted entirely", {"content": [_TEXT_A]}, ["message"]),
    # MCP permits several blocks, so multiplicity itself is not a defect.
    ("a well-formed image before the text",
     {"content": [{"type": "image", "data": "aGVsbG8=", "mimeType": "image/png"}, _TEXT_A]},
     ["message"]),
    ("the same text published twice", {"content": [_TEXT_A, _TEXT_A]}, ["message"]),
    ("result metadata alongside the content",
     {"content": [_TEXT_A], "isError": False, "_meta": {"trace": "abc"}}, ["message"]),
    # present and EQUAL is a correct server saying the same thing twice, and
    # refusing it would be a false kill
    ("structuredContent agreeing with the text block",
     {"content": [_TEXT_A], "structuredContent": {"channels": ["message"]}}, ["message"]),
])
def test_a_protocol_correct_tool_result_is_accepted(name, payload, expected):
    assert _tool_result_json(payload, "control") == {"channels": expected}


# ── the tools list ───────────────────────────────────────────────────────────

def _tool(enum):
    return {"name": "scan_text",
            "inputSchema": {"properties": {"channel": {"type": "string", "enum": enum}}}}


@pytest.mark.parametrize("name,tools", [
    # round 3: the fixture built a dict keyed by name, so the LAST definition won
    ("two definitions of one tool, the bad one first",
     [_tool(["message"]), _tool(["message", "file"])]),
    ("two definitions of one tool, the bad one last",
     [_tool(["message", "file"]), _tool(["message"])]),
    ("no such tool", [{"name": "scan_file"}]),
    ("tools is not an array", {"scan_text": _tool(["message"])}),
])
def test_a_tools_list_that_defines_the_tool_twice_or_not_at_all_is_refused(name, tools):
    with pytest.raises(WireError):
        _one_tool(tools, "scan_text", "control")


def test_one_definition_of_the_tool_is_accepted():
    tools = [{"name": "scan_file"}, _tool(["message", "file"]), {"name": "scanner_info"}]
    assert _one_tool(tools, "scan_text", "control") is tools[1]


def test_the_two_readers_compose_on_a_well_formed_pair():
    """The fixture's whole path, off the wire, with no server booted.

    Each reader above is proven alone. This proves they are the ones the fixture
    actually calls on a good wire -- the connection ASTRA showed could be cut in
    round 3 without a single named control going red.
    """
    wire = "\n".join([
        json.dumps({"jsonrpc": "2.0", "id": 2,
                    "result": {"tools": [_tool(["message", "file"])]}}),
        json.dumps({"jsonrpc": "2.0", "id": 3, "result": {
            "content": [{"type": "text", "text": '{"channels": ["message", "file"]}'}]}}),
    ])
    replies = parse_replies(wire)
    tool = _one_tool(replies[2]["result"]["tools"], "scan_text", "control")
    enum = _channel_enum(tool["inputSchema"]["properties"]["channel"], "control")
    info = _channel_list(_tool_result_json(replies[3]["result"], "control")["channels"],
                         "control")
    assert enum == info == {"message", "file"}


# ── THE CONNECTION CONTROL ───────────────────────────────────────────────────
# ASTRA, round 3: "direct helper controls prove less than a bounded full-fixture
# control: they establish helper behavior, but do not prove the fixture invokes
# it." Swapping ONE call in the fixture left all 33 tests green and made a
# known-defective wire pass again.
#
# These rows drive `read_surfaces` -- the exact function the fixture drives --
# with stdout built here instead of stdout from a subprocess. No server is
# booted, which is what makes it affordable to have one row per defect, and the
# reading path is shared, which is what makes cutting a call in it go red.

def _wire(*, channel_prop=None, info_channels=None, tools=None, content=None,
          list_id=2, info_id=3):
    """One server's stdout, with any one layer replaced by a defective shape."""
    nine = list(SunglassesEngine.DOCUMENTED_CHANNELS)
    prop = {"type": "string", "enum": nine} if channel_prop is None else channel_prop
    tool_list = [{"name": "scan_text", "inputSchema": {"properties": {"channel": prop}}}] \
        if tools is None else tools
    body = {"channels": nine if info_channels is None else info_channels}
    blocks = [{"type": "text", "text": json.dumps(body)}] if content is None else content
    return "\n".join([
        json.dumps({"jsonrpc": "2.0", "id": list_id, "result": {"tools": tool_list}}),
        json.dumps({"jsonrpc": "2.0", "id": info_id, "result": {"content": blocks}}),
    ])


_NINE = list(SunglassesEngine.DOCUMENTED_CHANNELS)


@pytest.mark.parametrize("name,stdout", [
    # every layer of the read, one defect each, through the fixture's own path
    ("a channel schema that permits none of its enum",
     _wire(channel_prop={"type": "integer", "enum": _NINE})),
    ("a channel schema excluding its enum by const",
     _wire(channel_prop={"type": "string", "enum": _NINE, "const": "nope"})),
    ("a channel schema with a keyword this reader does not account for",
     _wire(channel_prop={"type": "string", "enum": _NINE, "pattern": "^zzz$"})),
    ("scan_text defined twice with different enums",
     _wire(tools=[{"name": "scan_text",
                   "inputSchema": {"properties": {"channel": {"type": "string",
                                                              "enum": _NINE[:5]}}}},
                  {"name": "scan_text",
                   "inputSchema": {"properties": {"channel": {"type": "string",
                                                              "enum": _NINE}}}}])),
    ("two text blocks publishing different channel lists",
     _wire(content=[{"type": "text", "text": json.dumps({"channels": _NINE})},
                    {"type": "text", "text": json.dumps({"channels": _NINE[:5]})}])),
    ("an image block carrying text and no image",
     _wire(content=[{"type": "image", "text": "{}"},
                    {"type": "text", "text": json.dumps({"channels": _NINE})}])),
    ("the tools reply answered twice", _wire() + "\n" + _wire().splitlines()[0]),
    ("an id that is boolean true", _wire(list_id=True)),
])
def test_a_defective_wire_is_refused_by_the_path_the_fixture_uses(name, stdout):
    """Cut any call out of read_surfaces and one of these rows goes green."""
    with pytest.raises(WireError):
        read_surfaces(stdout)


def test_read_surfaces_accepts_a_correct_wire_and_returns_both_vocabularies():
    """Otherwise every row above passes by refusing everything."""
    got = read_surfaces(_wire())
    assert got["enum"] == got["info"] == set(SunglassesEngine.DOCUMENTED_CHANNELS)
