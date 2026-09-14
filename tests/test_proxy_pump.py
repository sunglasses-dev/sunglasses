"""The pump, specified from the contract rows BEFORE it exists.

Written this way deliberately. Three review rounds on the session core cost
ASTRA three passes, and the cause was the same each time: I wrote the tests my
implementation suggested, so they agreed with it. A test file written from the
rows, against a module that does not exist yet, cannot agree with an
implementation by construction, because there is nothing to agree with.

Every test below quotes the row it comes from. Where a row says something this
slice does not cover, the test is marked xfail with the reason, rather than
omitted, so the gap is visible in the run rather than in my memory.

Rows covered by this slice:

  T6.R1  a client request gets at most ONE response, with C's typed id
  T6.R2  an upstream result for a client id is delivered or withheld
  T6.R6  ids are (origin, type, value); "2001" is not 2001; the same typed id
         pending twice from C closes MALFORMED_CLIENT; an unsolicited or unknown
         response id from U closes MALFORMED_UPSTREAM; cancelled ids are
         rejected for reuse
  T7.R1  upstream exit with pending calls is an S5 trigger
  T7.R2  never resynchronise; a clean frame after the fault is discarded
"""
import json

import pytest

from sunglasses.proxy import framing

pump = pytest.importorskip("sunglasses.proxy.pump",
                           reason="the pump is the slice being specified here")


def wire(body):
    return json.dumps(body, separators=(",", ":")).encode() + b"\n"


def request(request_id, method="tools/call"):
    return {"jsonrpc": "2.0", "id": request_id, "method": method,
            "params": {"name": "read_text_file", "arguments": {"path": "/p"}}}


def response(request_id, text="ok"):
    return {"jsonrpc": "2.0", "id": request_id,
            "result": {"content": [{"type": "text", "text": text}]}}


# ── T6.R6: an id is a triple, not a value ──────────────────────────────────

def test_a_string_id_and_a_number_id_are_different_requests():
    """T6.R6: `"2001"` is not `2001`.

    A pump that keys by value alone answers one with the other, and the client
    cannot tell because both look like its own id coming back.
    """
    session = pump.Session()
    session.admit_request(2001, method="tools/call", origin="client")
    assert session.expects("2001", origin="client") is False
    assert session.expects(2001, origin="client") is True


def test_the_same_id_from_two_origins_is_two_requests():
    """T6.R6 keys by ORIGIN as well. An upstream request may legitimately carry
    an id a client request is already using, which is G2-15."""
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    session.admit_request(41, method="roots/list", origin="upstream")
    assert session.expects(41, origin="client")
    assert session.expects(41, origin="upstream")
    assert session.settle_from("upstream", 41, "UNINSPECTED_METHOD", "S3")
    assert session.expects(41, origin="client"), (
        "answering the upstream request retired the client's request, which is "
        "the G2-15 defect")


def test_the_same_typed_id_pending_twice_from_the_client_closes():
    """T6.R6: same typed id pending twice from C, MALFORMED_CLIENT, close."""
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    assert session.admit_request(41, method="tools/call", origin="client") is False
    assert session.closed_with() == ("MALFORMED_CLIENT", "S5")


def test_an_unsolicited_response_id_from_upstream_closes():
    """T6.R6: unsolicited or unknown response id from U, MALFORMED_UPSTREAM."""
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    session.deliver_response(origin="upstream", request_id=999)
    assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")


def test_a_cancelled_id_is_refused_for_reuse_for_the_session():
    """T6.R6. The tombstone outlives the request."""
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    session.cancel(41, origin="client")
    assert session.admit_request(41, method="tools/call", origin="client") is False


# ── T6.R1 and T6.R2: exactly one owner, exactly one answer ─────────────────

def test_a_client_request_gets_exactly_one_response_with_its_typed_id():
    """T6.R1: at most ONE response to C, carrying C's typed id."""
    session = pump.Session()
    session.admit_request("2001", method="tools/call", origin="client")
    first = session.deliver_response(origin="upstream", request_id="2001")
    assert first is not None
    assert first["id"] == "2001" and isinstance(first["id"], str)
    assert session.deliver_response(origin="upstream", request_id="2001") is None, (
        "a second upstream response for one client id produced a second answer")


# ── T7.R2: never resynchronise ─────────────────────────────────────────────

def test_a_clean_frame_after_a_protocol_fault_is_discarded():
    """T7.R2: never resynchronise at the next newline; a clean frame after the
    fault is discarded.

    The follower here is CLEAN on purpose. G2-10's own script follows its
    truncated frame with a well formed one carrying an injection, so a proxy
    that resynced would produce a detector finding and the finding would look
    like the mediator working.
    """
    stream = (b'{"jsonrpc":"2.0","id":41,"result":' + b"\n"
              + wire(response(41, "PERFECTLY-CLEAN")))
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    delivered = list(session.read_upstream(stream))
    assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")
    assert delivered == [], (
        "a frame after the fault reached the client, so the stream was resumed")


def test_the_item_owed_when_the_stream_faults_is_answered_not_stranded():
    """T7.R2 settles each KNOWN pending request once."""
    stream = b'{"jsonrpc":"2.0","id":41,"result":' + b"\n"
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    list(session.read_upstream(stream))
    assert session.answer_for(41, origin="client") is not None


# ── T7.R1: upstream exit with pending calls ────────────────────────────────

def test_upstream_exiting_with_a_pending_call_is_a_protocol_fault():
    """T7.R1 names it explicitly. A clean EOF is not a clean ending when the
    client is still owed an answer."""
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    list(session.read_upstream(b""))          # EOF with 41 outstanding
    assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")
    assert session.answer_for(41, origin="client") is not None


def test_upstream_exiting_with_nothing_pending_is_not_a_fault():
    """Or the check above would be calling every normal shutdown a fault."""
    session = pump.Session()
    list(session.read_upstream(b""))
    assert session.closed_with() is None


# ── T6.R2 response validation, which needs the pending method ──────────────

def test_a_response_whose_shape_does_not_match_the_request_is_refused():
    """G2-10/invalid_result_shape. `result.content` as a string where the
    request was a tools/call, which expects a list of blocks."""
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    bad = {"jsonrpc": "2.0", "id": 41, "result": {"content": "not a list"}}
    session.deliver_response(origin="upstream", request_id=41, frame=bad)
    assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")


# ── the same rows, on ASTRA's actual fixture bytes ─────────────────────────
# The tests above use frames built here. These read the seeds themselves, so the
# claim "the pump covers what Q12 and Q13 asked for" is checked against the
# bytes those checks read rather than against an analogue I wrote.

import pathlib

FIX = pathlib.Path("/private/tmp/PR164_REVIEW_f43781b_2026-09-13/fixtures")
fixtures = pytest.mark.skipif(not FIX.exists(),
                              reason=f"review fixtures not present at {FIX}")


@fixtures
def test_G2_10_invalid_result_shape_is_refused_by_the_pump():
    """Q13's first case, at the boundary where the ruling puts it.

    `parse_frame` cannot reject this alone and ASTRA said so: the frame is well
    formed JSON-RPC and only the REQUEST it answers makes its shape wrong. The
    pump knows the pending method, so it can.
    """
    lines = [x for x in (FIX / "G2-10" / "invalid_result_shape.upstream.jsonl"
                         ).read_bytes().splitlines() if x]
    frame = json.loads(lines[0])
    assert framing.parse_frame(lines[0]).ok, (
        "this frame is well formed on its own, which is the whole difficulty")

    session = pump.Session()
    session.admit_request(frame["id"], method="tools/call", origin="client")
    session.deliver_response(origin="upstream", request_id=frame["id"],
                             frame=frame)
    assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")


@fixtures
def test_G2_20_unsolicited_response_is_refused_by_the_pump():
    """Q13's second case. Nobody issued this id."""
    lines = [x for x in (FIX / "G2-20.unsolicited_response"
                         / "unsolicited_response.upstream.jsonl"
                         ).read_bytes().splitlines() if x]
    unsolicited = next(json.loads(x) for x in lines
                       if "result" in json.loads(x) or "error" in json.loads(x))
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    session.deliver_response(origin="upstream",
                             request_id=unsolicited["id"], frame=unsolicited)
    assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")
    assert session.answer_for(41, origin="client") is not None, (
        "the item that WAS owed was stranded by the close")


@fixtures
def test_G2_15_reverse_request_cannot_retire_the_client_item():
    """Q12, at the boundary. The upstream request deliberately reuses the
    client's id, and answering it must not answer the client."""
    folder = FIX / "G2-15.reverse_request"
    client = json.loads((folder / "reverse_request.requests.jsonl"
                         ).read_bytes().splitlines()[0])
    upstream = [json.loads(x) for x
                in (folder / "reverse_request.upstream.jsonl").read_bytes().splitlines()]
    reverse = next(x for x in upstream if "method" in x and "id" in x)
    assert reverse["id"] == client["id"], "the fixture shares the id on purpose"

    session = pump.Session()
    session.admit_request(client["id"], method=client.get("method", "tools/call"),
                          origin="client")
    session.admit_request(reverse["id"], method=reverse["method"],
                          origin="upstream")
    session.settle_from("upstream", reverse["id"], "UNINSPECTED_METHOD", "S3")

    assert session.expects(client["id"], origin="client"), (
        "answering the upstream request retired the client's request")
    assert session.closed_with() is None


def test_an_integer_id_and_a_float_id_do_not_collide():
    """T6.R6 stores the JSON TYPE in the key, and this is why it is not
    decoration.

    A mutation removing the type from the key survived every other test in this
    file, because Python already keeps `2001` and `"2001"` apart as dict keys,
    so the type component looked redundant. It is not: `1 == 1.0` is True and
    they hash equal, so `{1: x}[1.0]` returns x. Both are valid JSON-RPC ids,
    a client may issue one while upstream answers with the other, and without
    the type in the key the pump would hand one request's result to the other
    and the client could not tell.
    """
    assert 1 == 1.0 and hash(1) == hash(1.0), "the collision this guards"

    session = pump.Session()
    assert session.admit_request(1, method="tools/call", origin="client")
    assert session.admit_request(1.0, method="tools/list", origin="client"), (
        "1.0 was refused as a duplicate of 1, so the two collided")
    assert session.closed_with() is None, "a false duplicate closed the session"

    assert session.expected_method(1, origin="client") == "tools/call"
    assert session.expected_method(1.0, origin="client") == "tools/list"

    answer = session.deliver_response(origin="upstream", request_id=1,
                                      frame=response(1))
    assert answer is not None and type(answer["id"]) is int
    assert session.expects(1.0, origin="client"), (
        "answering the integer id also retired the float id")
