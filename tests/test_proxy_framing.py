"""T1.R2 and T7.R1: the parser, and which faults end a session.

The contract separates two things that look alike on the wire, and the whole
point of this file is to hold that separation:

  a PROTOCOL fault (S5) means the sender and we do not agree on what the message
  says, so nothing after it can be trusted and the session ends;

  a RESOURCE breach (S3 OVER_BUDGET) means the message is too big to inspect,
  which says nothing about whether the stream is still trustworthy.

Every test names the row it holds.
"""
import json

import pytest

from sunglasses.proxy import framing


def _frame(**fields):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}
    body.update(fields)
    return json.dumps(body).encode()


# ── T1.R2: what parses ──────────────────────────────────────────────────────

def test_an_ordinary_frame_parses_and_keeps_its_message():
    parsed = framing.parse_frame(_frame())
    assert parsed
    assert parsed.message["method"] == "tools/call"
    assert parsed.rule is None and parsed.reason is None


@pytest.mark.parametrize("raw,detail", [
    (b'{"jsonrpc":"2.0","id":1', "unparseable"),
    (b'not json at all', "unparseable"),
    (b'', "unparseable"),
])
def test_an_unparseable_line_is_a_protocol_fault(raw, detail):
    """T7.R1: unparseable is S5, not a budget question."""
    parsed = framing.parse_frame(raw)
    assert not parsed
    assert parsed.rule == framing.S5
    assert parsed.reason == framing.MALFORMED_UPSTREAM
    assert detail in parsed.detail


def test_invalid_utf8_is_a_protocol_fault_and_names_the_byte():
    parsed = framing.parse_frame(b'{"jsonrpc":"2.0","id":1,"m":"\xff\xfe"}')
    assert not parsed and parsed.rule == framing.S5
    assert "invalid UTF-8" in parsed.detail


def test_a_duplicate_key_is_rejected_rather_than_silently_resolved():
    """T1.R2's object_pairs_hook, and the reason it exists.

    `json.loads` keeps the LAST value for a repeated key and says nothing, which
    is the classic way to show a scanner one value and a server another. This is
    the one test whose absence would be invisible: the parse SUCCEEDS without
    the hook, so nothing else in this file would fail.
    """
    raw = b'{"jsonrpc":"2.0","id":1,"method":"a","method":"b"}'
    assert json.loads(raw)["method"] == "b", "the stdlib really does take the last"
    parsed = framing.parse_frame(raw)
    assert not parsed
    assert parsed.rule == framing.S5
    assert "duplicate key" in parsed.detail


@pytest.mark.parametrize("version", ["1.0", "2", 2.0, None, "2.0 "])
def test_anything_but_the_string_2_0_is_a_protocol_fault(version):
    parsed = framing.parse_frame(json.dumps(
        {"jsonrpc": version, "id": 1}).encode())
    assert not parsed and parsed.rule == framing.S5


def test_a_frame_claiming_both_result_and_error_is_refused():
    """T7.R1. A response is one or the other, and a frame claiming both leaves
    the reader to choose; whichever it chooses, the sender may have meant the
    other."""
    parsed = framing.parse_frame(json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {}, "error": {"code": -1}}).encode())
    assert not parsed and parsed.rule == framing.S5
    assert "both result and error" in parsed.detail


def test_a_top_level_array_is_not_a_frame():
    parsed = framing.parse_frame(b'[{"jsonrpc":"2.0","id":1}]')
    assert not parsed and parsed.rule == framing.S5
    assert "top level is list" in parsed.detail


# ── T1.R2: ids, and the bool that looks like a number ──────────────────────

@pytest.mark.parametrize("value", [1, -3, 0, 2.5, "abc", "", None])
def test_a_valid_id_keeps_its_json_type(value):
    parsed = framing.parse_frame(_frame(id=value))
    assert parsed, parsed.detail
    assert parsed.message["id"] == value
    assert type(parsed.message["id"]) is type(value)


@pytest.mark.parametrize("value", [True, False])
def test_a_boolean_is_not_a_number_however_much_python_thinks_so(value):
    """`isinstance(True, int)` is True, so a bool reaches a naive number check
    as a number.

    `true` is not a valid JSON-RPC id, and a proxy that accepted one would
    correlate a reply to something the client never asked. This is the
    resemblance the check has to refuse explicitly.
    """
    assert isinstance(value, int), "the trap this test exists for"
    assert framing.valid_id(value) is False
    parsed = framing.parse_frame(_frame(id=value))
    assert not parsed and parsed.rule == framing.S5
    assert "bool" in parsed.detail


@pytest.mark.parametrize("value", [{"a": 1}, ["x"]])
def test_a_structured_id_is_a_protocol_fault(value):
    parsed = framing.parse_frame(_frame(id=value))
    assert not parsed and parsed.rule == framing.S5


def test_a_notification_with_no_id_at_all_is_fine():
    """Absent is not invalid. A notification has no id and must still parse."""
    raw = json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled"}).encode()
    assert framing.parse_frame(raw)


# ── T4.R4(2): resource breaches are NOT protocol faults ────────────────────

def test_an_oversized_frame_is_a_budget_breach_and_is_never_parsed():
    """T8.R1. Parsing it is the cost the bound exists to refuse, so the refusal
    comes before the parse and the frame is deliberately valid JSON."""
    filler = "x" * (framing.MAX_FRAME_BYTES + 10)
    raw = json.dumps({"jsonrpc": "2.0", "id": 1, "pad": filler}).encode()
    parsed = framing.parse_frame(raw)
    assert not parsed
    assert parsed.rule == framing.S3, "an oversized frame is not a protocol fault"
    assert parsed.reason == framing.OVER_BUDGET
    assert parsed.budget == framing.BUDGET_FRAME
    assert parsed.message is None


def test_nesting_past_the_depth_limit_is_a_budget_breach_naming_depth():
    body = {"jsonrpc": "2.0", "id": 1, "deep": None}
    node = body
    for _ in range(framing.MAX_DEPTH + 5):
        node["deep"] = {"deep": None}
        node = node["deep"]
    parsed = framing.parse_frame(json.dumps(body).encode())
    assert not parsed
    assert parsed.rule == framing.S3 and parsed.budget == framing.BUDGET_DEPTH


def test_nesting_deep_enough_to_exhaust_the_parser_reports_the_same_cause():
    """The measurer must not fail first on exactly the input it measures.

    Past a few thousand levels the stdlib parser raises RecursionError before
    any depth can be counted. "We could not get far enough in to measure it" is
    not a different fact about the message from "it is too deep", so it is the
    same rule, the same reason and the same budget.
    """
    raw = (b'{"jsonrpc":"2.0","id":1,"deep":' + b"[" * 40_000
           + b"]" * 40_000 + b"}")
    parsed = framing.parse_frame(raw)
    assert not parsed
    assert parsed.rule == framing.S3 and parsed.budget == framing.BUDGET_DEPTH


def test_a_frame_just_inside_the_depth_limit_is_accepted():
    """Or the test above would pass for a parser that refused everything.

    The `method` is not decoration. An earlier version of this test built
    `{"jsonrpc": "2.0", "id": 1}` with nothing else, which is not a request, a
    notification or a response, and the envelope check added after ASTRA's
    review correctly refuses it. The test had been asserting that an invalid
    frame parses, and it passed because the parser had the same hole.
    """
    body = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    node = body
    for _ in range(framing.MAX_DEPTH - 3):
        node["deep"] = {}
        node = node["deep"]
    parsed = framing.parse_frame(json.dumps(body).encode())
    assert parsed, parsed.detail


def test_too_many_nodes_is_a_budget_breach_naming_nodes():
    """A frame well under the byte limit can still hold millions of nodes."""
    raw = json.dumps({"jsonrpc": "2.0", "id": 1,
                      "pad": [0] * (framing.MAX_NODES + 10)}).encode()
    assert len(raw) < framing.MAX_FRAME_BYTES, "this must not trip the frame bound"
    parsed = framing.parse_frame(raw)
    assert not parsed
    assert parsed.rule == framing.S3 and parsed.budget == framing.BUDGET_NODES


def test_object_keys_count_as_nodes():
    """An object of N keys is 2N+1 nodes, not N+1.

    Counting only values lets a frame carry twice the budget in keys, and T2.R0
    inspects every key as content, so they are exactly as expensive as values.
    """
    keys = {f"k{i}": 0 for i in range(framing.MAX_NODES // 2 + 50)}
    raw = json.dumps({"jsonrpc": "2.0", "id": 1, "pad": keys}).encode()
    parsed = framing.parse_frame(raw)
    assert not parsed and parsed.budget == framing.BUDGET_NODES


# ── T7.R3: which side is blamed ────────────────────────────────────────────

def test_the_origin_decides_which_side_is_named_and_nothing_else():
    raw = b'{"jsonrpc":"2.0","id":1,"a":1,"a":2}'
    upstream = framing.parse_frame(raw, origin="upstream")
    client = framing.parse_frame(raw, origin="client")
    assert upstream.reason == framing.MALFORMED_UPSTREAM
    assert client.reason == framing.MALFORMED_CLIENT
    assert upstream.rule == client.rule == framing.S5
    assert upstream.detail == client.detail

    # And it does NOT reach into the budget rules, which are about the message
    # rather than about who sent it.
    big = json.dumps({"jsonrpc": "2.0", "id": 1,
                      "pad": "x" * (framing.MAX_FRAME_BYTES + 10)}).encode()
    assert framing.parse_frame(big, origin="client").reason == framing.OVER_BUDGET


# ── AR15: a tail is not a frame ────────────────────────────────────────────

def test_an_unterminated_tail_is_not_yielded_as_a_frame():
    """AR15. The reader used to hand the caller whatever was in the buffer at
    EOF, so a partial line read as a complete one.

    On the client direction that meant forwarding an unterminated request to
    the server: the mediator delivering something nobody finished sending. "A
    frame is its bytes including the LF" is this module's own rule and it
    decides the EOF case too.
    """
    import io

    source = io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n{"partial"')
    tail = []
    frames = list(framing.bounded_lines(source, framing.MAX_FRAME_BYTES, tail))
    assert frames == [b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n']
    assert tail == [b'{"partial"']


def test_a_clean_ending_reports_no_tail():
    """The positive half, or the row above is satisfied by always reporting
    one."""
    import io

    source = io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
    tail = []
    frames = list(framing.bounded_lines(source, framing.MAX_FRAME_BYTES, tail))
    assert len(frames) == 1 and tail == []


def test_the_tail_list_is_optional():
    """Callers that do not care must not have to pass one, and the generator
    must not grow a None check in its hot loop."""
    import io

    source = io.BytesIO(b'{"partial"')
    assert list(framing.bounded_lines(source)) == []
