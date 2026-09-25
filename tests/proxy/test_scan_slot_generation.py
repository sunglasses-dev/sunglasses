"""T9 RULING 33. A scan slot belongs to ONE obligation generation.

ASTRA refused-4ff6983 r3. The slots that carry a scan's fields into a later
refusal were keyed on the typed id alone. A completed response left its fields
in `_scanned`, nothing cleared them when the client sent its next request, and
a client that reused the id -- which a finished id is free to do (C14) -- was
paid the OLD response's `complete/true/true` when its own receipt failed before
anything scanned it. The same stale slot also outranked the new request's own
scan.

The key is the obligation token, (origin, id-type, id, generation), the same
thing the receipts name, plus the direction the scan read.
"""
import itertools
import json

import pytest

from sunglasses.proxy.route import REQUEST, RESULT

from test_request_direction_receipt_fields import (_NOT_RUN, _route,
                                                   _scan_row, _told)
from test_result_direction_boundary import (_fail_receipts_at, _receipt_rows,
                                            _worker_result, wire)

_REQUEST = wire({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                 "params": {"name": "x", "arguments": {"a": "hello"}}})
_RESPONSE = wire({"jsonrpc": "2.0", "id": 1,
                  "result": {"content": [{"type": "text", "text": "hello"}]}})


def _complete_one_round_trip(route, out, home):
    """Request id 1 crosses clean, its response is scanned clean and delivered.
    Both scans must have RUN, or the stale slot under test never existed."""
    route.client_frame(_REQUEST)
    route.pump_upstream(_RESPONSE)
    delivered = [json.loads(raw) for raw in out if raw]
    assert len(delivered) == 1 and "result" in delivered[0], delivered
    scans = [r for r in _receipt_rows(home) if r.get("kind") == "SCAN_RESULT"]
    assert [r["status"] for r in scans] == ["complete", "complete"], scans
    del out[:]


def test_a_reused_id_after_a_completed_response_is_not_run(tmp_path):
    """The ASTRA sequence. Response id 1 was scanned and delivered; the client
    sends tools/call id 1 again and its HOLD_ENTERED receipt fails before
    anything scans it. The payer owes THIS request, and nothing inspected it."""
    route, out = _route(tmp_path)
    _complete_one_round_trip(route, out, tmp_path)
    fired = _fail_receipts_at(route, "HOLD_ENTERED")
    route.client_frame(_REQUEST)
    assert fired, "the HOLD_ENTERED receipt was never reached"
    assert _told(out) == _NOT_RUN


def test_a_reused_id_is_told_its_own_scan_not_the_last_response(
        tmp_path, tmp_path_factory):
    """The mirror. The reused request IS scanned, the scan is unusable, and
    writing its SCAN_RESULT fails: the client is told what THIS scan said, not
    the completed response's `complete/true/true`."""
    home = tmp_path_factory.mktemp("reference")
    reference, _ = _route(home, scan=lambda surface, **kw: {})
    reference.client_frame(_REQUEST)
    said = _scan_row(home)
    assert said["status"] != "complete", said

    calls = []

    def scan(surface, *, channel, binding, content_bytes):
        calls.append(channel)
        if len(calls) > 2:
            return {}
        return _worker_result(binding, content_bytes, False)

    route, out = _route(tmp_path, scan=scan)
    _complete_one_round_trip(route, out, tmp_path)
    fired = _fail_receipts_at(route, "SCAN_RESULT")
    route.client_frame(_REQUEST)
    assert fired and len(calls) == 3, (fired, calls)
    assert _told(out) == {"status": said["status"], "accepted": False,
                          "inspection_complete": False}


def test_a_paid_request_scan_cannot_be_told_again(tmp_path, tmp_path_factory):
    """T9 ruling 33, the CLIENT slot. A slot pays ONE answer. The request is
    scanned clean and its release authorisation fails before a byte crosses,
    so the refusal carries THIS scan's fields. Once that refusal is on the
    wire, the token it paid can no longer be told that scan, in either
    direction a payer asks."""
    home = tmp_path_factory.mktemp("reference")
    reference, _ = _route(home)
    reference.client_frame(_REQUEST)
    said = _scan_row(home)
    assert said["status"] == "complete", said

    route, out = _route(tmp_path)
    crossed = []
    route.upstream_write = crossed.append
    paid = []
    answered = route.session.answered_on_the_wire

    def recording(token, **kw):
        paid.append(token)
        return answered(token, **kw)

    route.session.answered_on_the_wire = recording
    fired = _fail_receipts_at(route, "RELEASE_AUTHORIZED")
    route.client_frame(_REQUEST)
    assert fired, "the RELEASE_AUTHORIZED receipt was never reached"
    # The slot existed and paid: nothing crossed (so `_cross_upstream` never
    # cleared it) and the refusal told the scan.
    assert crossed == [] and _told(out) == said, (crossed, out)
    assert len(paid) == 1, paid
    for direction in (None, REQUEST):
        assert route._scanned_fields(1, token=paid[0],
                                     direction=direction) == {}, direction


# The token a payer spends, and the same id's NEXT generation (a reused id).
_OWED = ("client", "int", 1, 1)
_NEXT = ("client", "int", 1, 2)
# Every state one slot can hold: empty, or a scan of either generation read in
# either direction.
_SLOT_STATES = [None] + [(token, direction, {"status": "complete"})
                         for token in (_OWED, _NEXT)
                         for direction in (REQUEST, RESULT)]


def _spend_as_the_loop_did(slots, owed):
    """a976f83's `_spend_scan`, over a dict so the reference itself computes
    no attribute name: every slot holding the owed token is emptied."""
    for slot in ("_scanned", "_scanned_request"):
        if slots[slot] is not None and slots[slot][0] == owed:
            slots[slot] = None
    return slots


@pytest.mark.parametrize("scanned, scanned_request",
                         list(itertools.product(_SLOT_STATES, repeat=2)))
def test_named_slot_clears_leave_what_the_loop_left(tmp_path, scanned,
                                                    scanned_request):
    """T9 R51. The named rewrite of `_spend_scan` (R3) leaves both slots
    exactly as the loop did, across slot x token x direction."""
    route, _ = _route(tmp_path)
    route._scanned, route._scanned_request = scanned, scanned_request
    route._spend_scan(_OWED)
    want = _spend_as_the_loop_did({"_scanned": scanned,
                                   "_scanned_request": scanned_request}, _OWED)
    assert {"_scanned": route._scanned,
            "_scanned_request": route._scanned_request} == want
