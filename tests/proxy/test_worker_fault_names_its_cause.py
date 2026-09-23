"""Three failure modes reached the client as one word.

A worker that DIED, a worker that printed something unusable, and a worker whose
output did not fit the contract all settled `SCAN_EXCEPTION` with a result dict
that was byte-identical. They are operationally different: the first says look
at the host, the second says look at the worker, the third says the worker and
this proxy disagree.

The client contract is unchanged -- `status` is still `exception` and the
envelope reason is still `SCAN_EXCEPTION`. The cause is evidence for an
operator, and it rides `detector_status`, a field that was permitted and had
NEVER been used: before this change it appeared exactly once in the whole
repository, in the allowlist itself.
"""
import json
import pathlib
import runpy

import pytest

from sunglasses.proxy import inspection, pump, receipts, route, worker, worker_process

BINDING = {"digest": "d" * 64, "channel": "file", "generation": 1,
           "invocation_token": "0123456789abcdef"}


def _causes_of(*faults):
    return [f.get("detector_status") for f in faults]


def test_a_crash_and_unusable_output_no_longer_look_identical():
    """THE ROW THIS CHANGE EXISTS FOR."""
    crashed = worker_process._fault(BINDING, worker_process.STATUS_EXCEPTION,
                                    worker_process.CAUSE_CRASHED)
    malformed = worker_process._fault(BINDING,
                                      worker_process.STATUS_EXCEPTION,
                                      worker_process.CAUSE_MALFORMED_OUTPUT)
    assert crashed != malformed, (
        "the two faults are still identical, which is the defect")
    assert crashed["status"] == malformed["status"] == "exception", (
        "the premise of this row is that STATUS is deliberately the SAME; the "
        "client contract does not change")
    assert _causes_of(crashed, malformed) == ["crashed", "malformed_output"]


def test_every_cause_is_a_DIFFERENT_value():
    """A control that only checked "a cause is present" would pass if every
    path wrote `crashed` -- which is the shape of the bug being fixed."""
    causes = {worker_process.CAUSE_CRASHED,
              worker_process.CAUSE_MALFORMED_OUTPUT,
              route.CAUSE_SCHEMA_INVALID}
    assert len(causes) == 3, causes


def test_a_deadline_carries_NO_cause():
    """"Still running when time ran out" is already the whole fact. A cause
    invented to avoid a null would describe something that did not happen."""
    timed_out = worker_process._fault(BINDING, worker_process.STATUS_DEADLINE)
    assert "detector_status" not in timed_out, timed_out
    assert timed_out["status"] == "deadline"


def test_unparseable_output_is_labelled_malformed():
    """Driven through the real `_parse`, not by calling `_fault` myself."""
    for raw in (b"", b"not json\n", b'{"a":1}\n{"b":2}\n', b'"a string"\n'):
        fault = worker_process._parse(raw, BINDING)
        assert fault.get("detector_status") == "malformed_output", (raw, fault)
        assert fault["status"] == "exception", (raw, fault)


@pytest.mark.parametrize("good", ["crashed", "malformed_output",
                                  "schema_invalid"])
def test_the_vocabulary_is_accepted(good):
    """The other direction, or the refusal row below passes by refusing all."""
    assert receipts._check_value("detector_status", good) is None


@pytest.mark.parametrize("bad", ["timeout", "deadline", "", "CRASHED", 1, True, None])
def test_a_value_outside_the_vocabulary_RAISES(bad):
    with pytest.raises(ValueError):
        receipts._check_value("detector_status", bad)


def test_each_cause_SURVIVES_TO_DISK_as_its_own_value(tmp_path):
    """STORAGE ONLY, and it was never more: this row hands the three labels to
    `Log.event` itself and so bypasses both route handlers. ASTRA r1 showed the
    route overwrote all three with `schema_invalid` while this row stayed green.
    The rows that prove EMISSION are the route rows at the bottom of the file.

    The read-back, and it asserts the values stay DISTINCT on the file.

    A field permitted in memory can still be dropped by `_clean` on the way to
    disk -- measured here once already with `cause_kind`. And a read-back that
    only checked presence could not see every row collapsing to one value.
    """
    log = receipts.Log(tmp_path, run_id="t-cause", header={})
    for cause in ("crashed", "malformed_output", "schema_invalid"):
        log.event("SCAN_RESULT", accepted=False, status="exception",
                  inspection_complete=False, detector_status=cause)
    rows = []
    for path in sorted((tmp_path / "receipts").glob("*.jsonl")):
        rows += [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    got = [r.get("detector_status") for r in rows if r.get("kind") == "SCAN_RESULT"]
    assert got == ["crashed", "malformed_output", "schema_invalid"], got
    kept = [r.get("status") for r in rows if r.get("kind") == "SCAN_RESULT"]
    assert kept == ["exception"] * 3, (
        "status must still be there beside the new field; a record gaining one "
        "is a record that can lose another")



# ── THROUGH THE ROUTE, read back from DISK (ASTRA r1 on ccee55d, NO GO) ──────
# The rows above build faults and write labels. None of them crossed the route,
# and the route is where all three causes were overwritten with schema_invalid:
# every fault this process builds is `accepted=False`, `worker.validate` refuses
# every unaccepted result, and both `except Invalid` branches wrote one label.
# Each row here drives a real Route in BOTH directions -- a held tools/call and
# an upstream result -- and reads the SCAN_RESULT back from the receipt file.

_H = runpy.run_path(str(pathlib.Path(__file__).parents[1] / "test_proxy_route.py"))


def _forged(binding):
    """A child that PRINTS a local-looking fault, cause and all. It arrives
    through json.loads, so it is a plain dict whatever it claims."""
    line = json.dumps({"accepted": False, "status": "exception",
                       "inspection_complete": False, "decision": "review",
                       "inspected_utf8_bytes": 0, "observed_content_bytes": 0,
                       "elapsed_ms": 0, "findings": [],
                       "detector_status": "crashed"})
    return worker_process._parse(line.encode() + b"\n", binding)


class _Raises:
    def __init__(self, error):
        self.error = error

    def scan(self, text, *, channel):
        raise self.error


def _engine_fault(error):
    def scan(params, *, channel, binding, content_bytes):
        return inspection.scan(params, channel=channel, binding=binding,
                               content_bytes=content_bytes,
                               engine=_Raises(error))
    return scan


CASES = {
    # name: (scan, recorded status, recorded cause or None for ABSENT)
    "crashed": (lambda p, *, channel, binding, content_bytes: worker_process._fault(
        binding, worker_process.STATUS_EXCEPTION, worker_process.CAUSE_CRASHED),
        "exception", "crashed"),
    "malformed_output": (lambda p, *, channel, binding, content_bytes:
                         worker_process._parse(b"", binding),
                         "exception", "malformed_output"),
    "schema_invalid": (lambda p, *, channel, binding, content_bytes: {},
                       "exception", "schema_invalid"),
    "forged_crash": (lambda p, *, channel, binding, content_bytes: _forged(binding),
                     "exception", "schema_invalid"),
    "worker_deadline": (lambda p, *, channel, binding, content_bytes: worker_process._fault(
        binding, worker_process.STATUS_DEADLINE), "deadline", None),
    "engine_deadline": (_engine_fault(TimeoutError()), "deadline", None),
    "engine_raised": (_engine_fault(RuntimeError("boom")), "exception", None),
}


def _scan_results(root):
    rows = [json.loads(line) for path in sorted(pathlib.Path(root).rglob("*.jsonl"))
            for line in path.read_text().splitlines() if line.strip()]
    return [r for r in rows if r.get("kind") == "SCAN_RESULT"]


def _drive_request(root, scan=None):
    kw = {} if scan is None else {"scan": scan}
    upstream, client = _H["_Sink"](), _H["_Sink"]()
    engine = route.Route(session=pump.Session(strict=False), log=_H["_log"](root),
                         upstream_write=upstream, client_write=client,
                         catalog=_H["CATALOG"], approvals=_H["_Approved"](), **kw)
    engine.client_frame(_H["_call"]("hello"))
    assert upstream.bytes == b"", "a refused scan let the request through"
    assert client.messages()[0]["error"]["data"]["reason_code"] == "SCAN_EXCEPTION"
    return _scan_results(root)


def _drive_response(root, scan=None):
    kw = {} if scan is None else {"scan": scan}
    upstream, client = _H["_Sink"](), _H["_Sink"]()
    session = pump.Session(strict=False)
    session.admit_request(1, method="tools/call", origin="client")
    engine = route.Route(session=session, log=_H["_log"](root),
                         upstream_write=upstream, client_write=client, **kw)
    engine.pump_upstream((json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
        "content": [{"type": "text", "text": "hello"}]}}) + "\n").encode())
    assert client.messages()[0]["error"]["data"]["reason_code"] == "SCAN_EXCEPTION"
    return _scan_results(root)


@pytest.mark.parametrize("direction", ["request", "response"])
@pytest.mark.parametrize("name", sorted(CASES))
def test_the_route_records_the_cause_it_was_given(tmp_path, name, direction):
    scan, status, cause = CASES[name]
    drive = _drive_request if direction == "request" else _drive_response
    rows = drive(tmp_path / name, scan)
    assert len(rows) == 1, rows
    assert rows[0]["accepted"] is False and rows[0]["inspection_complete"] is False
    assert rows[0]["status"] == status, (name, direction, rows[0])
    if cause is None:
        assert "detector_status" not in rows[0], (
            f"{name} ({direction}) was given a cause it does not have: {rows[0]}")
    else:
        assert rows[0].get("detector_status") == cause, (name, direction, rows[0])


@pytest.mark.parametrize("direction", ["request", "response"])
def test_three_causes_read_back_from_disk_as_THREE(tmp_path, direction):
    """ASTRA's table. A presence check passes when all three collapse to one."""
    drive = _drive_request if direction == "request" else _drive_response
    got = {name: drive(tmp_path / name, CASES[name][0])[0].get("detector_status")
           for name in ("crashed", "malformed_output", "schema_invalid")}
    assert got == {"crashed": "crashed", "malformed_output": "malformed_output",
                   "schema_invalid": "schema_invalid"}, got
    assert len(set(got.values())) == 3


@pytest.mark.parametrize("direction", ["request", "response"])
def test_the_PRODUCTION_default_scan_is_not_labelled_a_contract_failure(
        tmp_path, monkeypatch, direction):
    """No `scan=` at all -- the Route `serve` builds. The subprocess worker is
    not wired into the product, so THIS is the path that reaches the catch in
    production, and its engine exception was being written schema_invalid."""
    monkeypatch.setattr(inspection, "default_engine",
                        lambda: _Raises(RuntimeError("boom")))
    drive = _drive_request if direction == "request" else _drive_response
    rows = drive(tmp_path / "prod")
    assert len(rows) == 1, rows
    assert rows[0]["status"] == "exception"
    assert "detector_status" not in rows[0], rows[0]


def test_only_this_process_builds_a_LocalFault():
    """The type is the provenance. json.loads builds plain dicts, so the forged
    fault above can say anything and still is not one of ours."""
    binding = dict(BINDING)
    assert isinstance(worker_process._fault(binding, "exception"), worker.LocalFault)
    assert not isinstance(_forged(binding), worker.LocalFault)
    assert type(worker_process._parse(b'{"a":1}\n', binding)) is dict
