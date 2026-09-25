"""A refused result's SCAN_RESULT names its fields, and a field nobody named
cannot cost the client its answer.

#172 closed the receipt row keys, so the two refused-result sites write
`status` and `detector_status` by name through `Route._record_unusable`. The
first draft of that helper raised on any other key. The raise ran inside the
readers, and serve.py's readers swallow what escapes them: measured on
b0a5223a, the reader stopped with the id unanswered, no SCAN_RESULT and the
session open, in both directions. The old splice had answered the client.

So the key set is pinned where it is made, in `_unusable`, at test time; and a
forced extra key must leave the client answered and the named fields written.
"""
import json
import pathlib
import runpy

import pytest

from sunglasses.proxy import pump, route, worker, worker_process

_H = runpy.run_path(str(pathlib.Path(__file__).parents[1] / "test_proxy_route.py"))

NAMED = {"status", "detector_status"}

RESULTS = {
    "fault_with_cause": worker.LocalFault(
        status=worker_process.STATUS_EXCEPTION,
        detector_status=worker_process.CAUSE_CRASHED),
    "fault_without_cause": worker.LocalFault(status="deadline"),
    "fault_with_null_cause": worker.LocalFault(
        status=worker_process.STATUS_EXCEPTION, detector_status=None),
    "contract_failure": {},
    "worker_typed_a_cause": {"status": "exception",
                             "detector_status": worker_process.CAUSE_CRASHED},
}


@pytest.mark.parametrize("name", sorted(RESULTS))
def test_unusable_carries_only_the_fields_the_record_names(name):
    fields = route._unusable(RESULTS[name])
    assert set(fields) <= NAMED, sorted(fields)
    assert "status" in fields, fields
    assert fields.get("detector_status", "omitted") is not None, fields


def _contract_failure(params, *, channel, binding, content_bytes):
    return {}


def _rows(root):
    return [json.loads(line) for path in sorted(pathlib.Path(root).rglob("*.jsonl"))
            for line in path.read_text().splitlines() if line.strip()]


def _drive(root, direction):
    upstream, client = _H["_Sink"](), _H["_Sink"]()
    session = pump.Session(strict=False)
    kw = dict(session=session, log=_H["_log"](root), upstream_write=upstream,
              client_write=client, scan=_contract_failure)
    if direction == "result":
        session.admit_request(1, method="tools/call", origin="client")
        route.Route(**kw).pump_upstream((json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
            "content": [{"type": "text", "text": "hello"}]}}) + "\n").encode())
    else:
        route.Route(approvals=_H["_Approved"](), **kw).client_frame(_H["_call"]("hello"))
    assert upstream.bytes == b""
    return client.messages(), _rows(root)


@pytest.mark.parametrize("direction", ["request", "result"])
def test_an_unnamed_field_still_answers_the_client(tmp_path, monkeypatch, direction):
    real = route._unusable
    monkeypatch.setattr(route, "_unusable", lambda result: {**real(result), "surprise": "x"})
    answered, rows = _drive(tmp_path, direction)
    assert len(answered) == 1, answered
    data = answered[0]["error"]["data"]
    assert (data["reason_code"], data["status"]) == ("SCAN_EXCEPTION", "exception"), data
    scanned = [r for r in rows if r.get("kind") == "SCAN_RESULT"]
    assert len(scanned) == 1, [r.get("kind") for r in rows]
    assert scanned[0]["detector_status"] == route.CAUSE_SCHEMA_INVALID, scanned[0]
    assert "surprise" not in scanned[0], scanned[0]


@pytest.mark.parametrize("direction", ["request", "result"])
def test_the_control_with_no_extra_field_the_row_is_the_same(tmp_path, direction):
    answered, rows = _drive(tmp_path, direction)
    assert len(answered) == 1, answered
    scanned = [r for r in rows if r.get("kind") == "SCAN_RESULT"]
    assert [r["detector_status"] for r in scanned] == [route.CAUSE_SCHEMA_INVALID]
