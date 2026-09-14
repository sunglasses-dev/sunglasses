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
