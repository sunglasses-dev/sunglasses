"""T9 RULING 14 in the CLIENT direction.

The result-direction rows (test_result_direction_boundary.py) hold the rule
for a response. A request has the same shape and had the same defect, found by
measurement while fixing the other: a receipt failure at SCAN_RESULT or at the
release authorisation told the client `not_run` while the scan had run, and at
the release authorisation its SCAN_RESULT of `complete` was already on disk.

(a) No scan result exists -> `not_run`. (b) A result exists and a receipt write
fails before the request crosses -> the scan's three real fields, reason
RECEIPT_IO_ERROR. (c) The request has crossed -> what the client is owed is
the RESPONSE, which nothing scanned, so `not_run` again.
"""
import json
import types

import pytest

from sunglasses.proxy import pump, receipts
from sunglasses.proxy.route import Route

from test_result_direction_boundary import (_fail_receipts_at, _reason_codes,
                                            _receipt_rows, _worker_result, wire)

_REQUEST = wire({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                 "params": {"name": "x", "arguments": {"a": "hello"}}})
_NOT_RUN = {"status": "not_run", "accepted": False, "inspection_complete": False}
# event -> does the client's refusal carry the scan's fields?
_TELLS_THE_SCAN = {"HOLD_ENTERED": False, "SCAN_STARTED": False,
                   "SCAN_RESULT": True, "RELEASE_AUTHORIZED": True,
                   "WRITE_COMPLETE": False}


def _route(home, *, finding=False, scan=None):
    out = []
    route = Route(session=pump.Session(strict=False),
                  log=receipts.Log(home, run_id="review", header={}),
                  upstream_write=lambda raw: None, client_write=out.append,
                  scan=scan or (lambda surface, *, channel, binding, content_bytes:
                                _worker_result(binding, content_bytes, finding)),
                  catalog={"GLS-SD-001", "GLS-PI-001"},
                  approvals=types.SimpleNamespace(may_call=lambda *a: None,
                                                  invalidate=lambda: None))
    return route, out


def _scan_row(home):
    rows = [r for r in _receipt_rows(home) if r.get("kind") == "SCAN_RESULT"]
    assert len(rows) == 1, rows
    return {f: rows[0][f] for f in ("status", "accepted", "inspection_complete")}


def _told(out):
    assert _reason_codes(out) == ["RECEIPT_IO_ERROR"], _reason_codes(out)
    data = json.loads([raw for raw in out if raw][0])["error"]["data"]
    return {f: data[f] for f in ("status", "accepted", "inspection_complete")}


@pytest.mark.parametrize("event", sorted(_TELLS_THE_SCAN))
def test_a_request_refused_by_its_receipt_says_what_its_scan_did(
        tmp_path, tmp_path_factory, event):
    home = tmp_path_factory.mktemp("reference")
    reference, _ = _route(home)
    reference.client_frame(_REQUEST)
    said = _scan_row(home)
    assert said["status"] == "complete", said

    route, out = _route(tmp_path)
    fired = _fail_receipts_at(route, event)
    route.client_frame(_REQUEST)
    assert fired, f"the {event} receipt was never reached"
    told = _told(out)
    assert told == (said if _TELLS_THE_SCAN[event] else _NOT_RUN), (event, told)


def test_a_request_whose_scan_failed_and_whose_record_failed_says_it_ran(
        tmp_path, tmp_path_factory):
    home = tmp_path_factory.mktemp("reference")
    reference, _ = _route(home, scan=lambda surface, **kw: {})
    reference.client_frame(_REQUEST)
    said = _scan_row(home)
    assert said["status"] != "not_run", said

    route, out = _route(tmp_path, scan=lambda surface, **kw: {})
    fired = _fail_receipts_at(route, "SCAN_RESULT")
    route.client_frame(_REQUEST)
    assert fired
    assert _told(out) == {"status": said["status"], "accepted": False,
                          "inspection_complete": False}


def test_a_reused_id_does_not_inherit_the_earlier_scan(tmp_path):
    """The slot is per request, not per id. Request 7 is WITHHELD (answered,
    its slot left behind); the client reuses id 7, and that request is refused
    at HOLD_ENTERED before anything scanned it: `not_run`, not the first
    request's `complete`."""
    route, out = _route(tmp_path, finding=True)
    route.client_frame(_REQUEST)
    assert _reason_codes(out) == ["PROHIBITED_SECRET"], _reason_codes(out)
    del out[:]
    _fail_receipts_at(route, "HOLD_ENTERED")
    route.client_frame(_REQUEST)
    assert _told(out) == _NOT_RUN
