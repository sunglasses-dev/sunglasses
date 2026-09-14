"""T6.R6's proxy control ids, specified from the rows before the seam exists.

T2.R6 says the proxy RE-LISTS in its own id namespace and T6.R6 says its
control traffic uses `sg-<uuid>`. That is not a style rule. One client
`tools/list` becomes up to sixty four proxy requests under T8.R13, and the
client's single id can answer exactly one of them, so the proxy has to own ids
of its own or it cannot page a tool list at all.

T9 approved this on 2026-09-14 as designed, and the approval names three things
it must not become. Those three are the acceptance and each has a mutation that
must go red:

  ONE TABLE. Not a second correlation dict living beside the first. Two tables
  drift, and the one that drifts is the one holding the tombstones, so a
  cancelled id becomes reusable in the namespace nobody was watching.

  A CLIENT CANNOT CLAIM THE NAMESPACE. An `sg-` prefixed id arriving from the
  client is MALFORMED_CLIENT. If it were accepted as control traffic, the
  prefix would be an authentication claim that anyone on the other end of the
  pipe can make, and the client could settle the proxy's own pending requests.

  THE READER NEVER BLOCKS ON THE COLLECTOR. The collector runs on the thread
  handling the client's call; the reader hands it pages. If the reader waited
  for the collector to take them, a collector that stops consuming stalls the
  pump, and the pump is what would have noticed the upstream dying.
"""
import threading
import time

import pytest

from sunglasses.proxy import pump

pytestmark = pytest.mark.skipif(
    not hasattr(pump, "ORIGIN_PROXY"),
    reason="the proxy control namespace is the slice being specified")


def wire(value):
    import json
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


def _result(request_id, tools=()):
    return {"jsonrpc": "2.0", "id": request_id,
            "result": {"tools": [{"name": name} for name in tools]}}


# ── the namespace itself ─────────────────────────────────────────────────

def test_a_proxy_response_is_handed_over_and_never_yielded_to_the_client():
    """T2.R6. The client asked once; these are our requests, and a client that
    saw them would be reading a conversation it is not part of."""
    session = pump.Session()
    session.admit_request("sg-1", method="tools/list", origin=pump.ORIGIN_PROXY)
    delivered = list(session.read_upstream(wire(_result("sg-1", ["echo"]))))
    assert delivered == [], "a proxy control response reached the client"
    assert session.control_answer("sg-1")["result"]["tools"] == [{"name": "echo"}]


def test_the_session_stays_open_after_a_control_exchange():
    """An unsolicited response closes the session under T6.R6, so a control
    response the reader failed to recognise would tear down a healthy session
    on the proxy's own traffic."""
    session = pump.Session()
    session.admit_request("sg-1", method="tools/list", origin=pump.ORIGIN_PROXY)
    list(session.read_upstream(wire(_result("sg-1"))))
    assert session.closed_with() is None


def test_a_control_id_and_a_client_id_of_the_same_value_are_different_items():
    """ONE TABLE, keyed by origin. The two namespaces share a table and are
    told apart by the key, not by living in separate dicts."""
    session = pump.Session()
    assert session.admit_request("sg-1", method="tools/list",
                                 origin=pump.ORIGIN_PROXY)
    assert session.admit_request("sg-1", method="tools/call",
                                 origin=pump.ORIGIN_CLIENT)
    assert session.closed_with() is None, "the second was read as a duplicate"


def test_an_unknown_control_id_is_still_an_unsolicited_response():
    """The namespace is not a bypass. An `sg-` id we never issued is exactly as
    unsolicited as any other, or a server can invent control traffic."""
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin=pump.ORIGIN_CLIENT)
    list(session.read_upstream(wire(_result("sg-never-issued"))))
    assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")


# ── the client cannot claim the namespace ────────────────────────────────

def test_a_client_using_the_control_prefix_is_malformed_client():
    """The prefix would otherwise be an authentication claim anyone can make,
    and a client that owns a control id can settle the proxy's own request."""
    session = pump.Session()
    assert session.admit_request("sg-1", method="tools/call",
                                 origin=pump.ORIGIN_CLIENT) is False
    assert session.closed_with() == ("MALFORMED_CLIENT", "S5")


def test_an_ordinary_client_id_is_still_admitted():
    """The positive control. Without it, a session that refuses every client
    request passes the test above."""
    session = pump.Session()
    assert session.admit_request("sg", method="tools/call",
                                 origin=pump.ORIGIN_CLIENT) is True
    assert session.admit_request(41, method="tools/call",
                                 origin=pump.ORIGIN_CLIENT) is True
    assert session.closed_with() is None


# ── the reader never blocks ──────────────────────────────────────────────

def test_a_collector_that_never_consumes_does_not_stall_the_reader():
    """The pump is what notices the upstream dying. If it waited on a consumer
    that stopped consuming, a stuck collector would take the watchdog with it.

    Bounded by a wall clock rather than by a queue's own promise, because the
    thing being asserted is that this call RETURNS.
    """
    session = pump.Session()
    for n in range(64):
        session.admit_request(f"sg-{n}", method="tools/list",
                              origin=pump.ORIGIN_PROXY)
    stream = b"".join(wire(_result(f"sg-{n}")) for n in range(64))

    done = threading.Event()

    def drive():
        list(session.read_upstream(stream))
        done.set()

    thread = threading.Thread(target=drive, daemon=True)
    started = time.monotonic()
    thread.start()
    assert done.wait(5), "the reader blocked with nobody taking the pages"
    assert time.monotonic() - started < 5


def test_the_pages_are_all_there_when_the_collector_does_come_for_them():
    """The other half. A hand-off that never blocks is easy if it drops."""
    session = pump.Session()
    for n in range(8):
        session.admit_request(f"sg-{n}", method="tools/list",
                              origin=pump.ORIGIN_PROXY)
    list(session.read_upstream(
        b"".join(wire(_result(f"sg-{n}", [f"t{n}"])) for n in range(8))))
    for n in range(8):
        answer = session.control_answer(f"sg-{n}")
        assert answer["result"]["tools"] == [{"name": f"t{n}"}]
