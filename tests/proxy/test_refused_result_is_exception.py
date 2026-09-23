"""A result the proxy SCANNED and then refused is not a scan that never ran.

When `worker.validate` refuses a result, both route catches record the
SCAN_RESULT with its real status -- `exception`, or `deadline` for a scan that
ran out of time -- and then build the client's envelope with no settlement, so
it fell to the `"not_run"` default. The receipt said the scan ran and failed;
the client was told it never ran. Found by T10 on 9-23, measured on c7c7072.

Each row compares the two in ONE place: the envelope the client got and the
SCAN_RESULT read back from the receipt file must say the same status.

The CAUSE stays in the receipt. The envelope is a fixed key set by design
(`envelope.withheld` drops anything extra), and the 9-22 design ruling kept the
client contract at `SCAN_EXCEPTION` + status; only the status was wrong.

CONTROL: paths that genuinely never scan -- an unapproved call, a result for a
method with no channel -- still say `not_run`, and write no SCAN_RESULT at all.
"""
import json
import pathlib
import runpy

import pytest

from sunglasses.proxy import inspection, pump, route, worker_process

_H = runpy.run_path(str(pathlib.Path(__file__).parents[1] / "test_proxy_route.py"))


class _Raises:
    def __init__(self, error):
        self.error = error

    def scan(self, text, *, channel):
        raise self.error


def _engine_fault(error):
    def scan(params, *, channel, binding, content_bytes):
        return inspection.scan(params, channel=channel, binding=binding,
                               content_bytes=content_bytes, engine=_Raises(error))
    return scan


CASES = {
    # name: (scan, status the receipt AND the envelope must carry)
    "engine_raised": (_engine_fault(RuntimeError("boom")), "exception"),
    "engine_deadline": (_engine_fault(TimeoutError()), "deadline"),
    "worker_crashed": (lambda p, *, channel, binding, content_bytes: worker_process._fault(
        binding, worker_process.STATUS_EXCEPTION, worker_process.CAUSE_CRASHED),
        "exception"),
    "contract_failure": (lambda p, *, channel, binding, content_bytes: {}, "exception"),
}


def _rows(root):
    return [json.loads(line) for path in sorted(pathlib.Path(root).rglob("*.jsonl"))
            for line in path.read_text().splitlines() if line.strip()]


def _request(root, scan, approvals=None):
    upstream, client = _H["_Sink"](), _H["_Sink"]()
    engine = route.Route(session=pump.Session(strict=False), log=_H["_log"](root),
                         upstream_write=upstream, client_write=client,
                         approvals=approvals or _H["_Approved"](), scan=scan)
    engine.client_frame(_H["_call"]("hello"))
    assert upstream.bytes == b""
    return client.messages()[0]["error"]["data"], _rows(root)


def _response(root, scan, method="tools/call"):
    upstream, client = _H["_Sink"](), _H["_Sink"]()
    session = pump.Session(strict=False)
    session.admit_request(1, method=method, origin="client")
    engine = route.Route(session=session, log=_H["_log"](root),
                         upstream_write=upstream, client_write=client, scan=scan)
    engine.pump_upstream((json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
        "content": [{"type": "text", "text": "hello"}]}}) + "\n").encode())
    return client.messages()[0]["error"]["data"], _rows(root)


@pytest.mark.parametrize("direction", ["request", "response"])
@pytest.mark.parametrize("name", sorted(CASES))
def test_the_client_is_told_the_status_the_receipt_records(tmp_path, name, direction):
    scan, status = CASES[name]
    drive = _request if direction == "request" else _response
    data, rows = drive(tmp_path / name, scan)
    results = [r for r in rows if r.get("kind") == "SCAN_RESULT"]
    assert len(results) == 1, results
    assert results[0]["status"] == status, results[0]
    assert data["reason_code"] == "SCAN_EXCEPTION"
    assert data["status"] == results[0]["status"], (
        f"{name} ({direction}): the receipt says {results[0]['status']!r} and "
        f"the client was told {data['status']!r}")
    assert data["accepted"] is False and data["inspection_complete"] is False


def test_CONTROL_an_unapproved_call_never_scanned_and_says_so(tmp_path):
    data, rows = _request(tmp_path, CASES["engine_raised"][0],
                          approvals=_H["_Unapproved"]())
    assert data["status"] == "not_run", data
    assert not [r for r in rows if r.get("kind") in ("SCAN_STARTED", "SCAN_RESULT")]


def test_CONTROL_a_result_with_no_channel_never_scanned_and_says_so(tmp_path):
    data, rows = _response(tmp_path, CASES["engine_raised"][0],
                           method="resources/list")
    assert data["reason_code"] == "UNINSPECTED_METHOD", data
    assert data["status"] == "not_run", data
    assert not [r for r in rows if r.get("kind") in ("SCAN_STARTED", "SCAN_RESULT")]
