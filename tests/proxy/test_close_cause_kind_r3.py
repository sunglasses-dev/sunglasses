"""R-CLOSE-KIND-R3: a close names WHICH fault, and the receipt agrees with it.

#185's subject is a close naming which fault from a fixed vocabulary, with the
receipt agreeing with the wire. These two rows are the cases where it did not.

Both were reproduced on unmodified trees before anything was written, with
re-runnable probes in `warroom/r185-followups/`, because a claim nobody can
re-run is a claim. Item 1 reproduced on main AND on #168's head; item 2 on
bb7607b, 07c5c67 and cf294f5.
"""
import json
import pathlib
import threading
import types

import pytest

from sunglasses.proxy import pump, receipts
from sunglasses.proxy.route import Route


def _rows(log):
    return [json.loads(line) for line in
            log.path.read_text().splitlines() if line.strip()]


# ── item 1 · the cause the client was told is the cause on the record ────────

def test_a_close_mid_write_does_not_rename_the_cause_the_client_was_told(tmp_path):
    """One item must not have two accounts of how it ended.

    A local approval refusal is paused inside the client sink. A legitimate
    close terminalises the core item with ITS cause. The writer resumes. The
    client holds a frame saying APPROVAL_REQUIRED; the record said
    MALFORMED_UPSTREAM, and nothing raised.

    Settling earlier is NOT the repair -- #179's
    `test_a_locally_claimed_answer_still_counts_against_the_bound` requires an
    answer mid-write to stay outstanding, and settling releases the
    correlation. So the CAUSE is committed before the bytes while the
    CORRELATION stays outstanding, and the close settles a committed item with
    the cause its frame carries.
    """
    out, entered, release, errors = [], threading.Event(), threading.Event(), []

    def client_write(raw):
        out.append(raw)
        entered.set()
        assert release.wait(5), "the test never released the writer"

    session = pump.Session()
    log = receipts.Log(tmp_path, run_id="r3", header={})
    route = Route(session=session, log=log, client_write=client_write,
                  upstream_write=lambda raw: None, catalog=(),
                  approvals=types.SimpleNamespace(
                      may_call=lambda *a: "APPROVAL_REQUIRED",
                      invalidate=lambda: None))

    def offer():
        try:
            route.client_frame((json.dumps(
                {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                 "params": {"name": "review"}}) + "\n").encode())
        except Exception as error:                     # noqa: BLE001
            errors.append(type(error).__name__)

    worker = threading.Thread(target=offer)
    worker.start()
    assert entered.wait(3), "the writer never reached the sink"
    session._close("MALFORMED_UPSTREAM", "racing close")
    release.set()
    worker.join(5)
    log.close()

    assert not errors, errors
    wire = [json.loads(b).get("error", {}).get("data", {}).get("reason_code")
            for b in out if b]
    core = [cause.reason for cause in session._core._settled.values()]
    assert wire == ["APPROVAL_REQUIRED"], wire
    assert core == ["APPROVAL_REQUIRED"], (
        f"the client was told {wire} and the record says {core}: one item, two "
        f"accounts of how it ended")


# ── item 2 · an invalidated session forwards no notification ────────────────

def _invalidated_route(tmp_path):
    out = []
    session = pump.Session()
    assert session.admit_request(1, method="tools/call", origin="client")
    log = receipts.Log(tmp_path, run_id="r3n", header={})
    route = Route(session=session, log=log, client_write=out.append,
                  upstream_write=lambda raw: None, catalog=(),
                  approvals=types.SimpleNamespace(may_call=lambda *a: None,
                                                  invalidate=lambda: None))
    session._invalidated_as = "DESCRIPTOR_CHANGED"
    return session, route, log, out


def _notification():
    return (json.dumps({"jsonrpc": "2.0", "method": "notifications/message",
                        "params": {"data": "notice"}}) + "\n").encode()


def test_an_invalidated_session_does_not_forward_a_notification(tmp_path):
    """The descriptors moved, so this frame is something an unapproved server
    said. Responses were already covered because they carry an id and the
    record gate reaches them; a notification carries none and went out anyway.
    """
    _session, route, log, out = _invalidated_route(tmp_path)
    route.pump_upstream(_notification())
    log.close()

    crossed = [f for f in (json.loads(b) for b in out if b) if "method" in f]
    assert not crossed, (
        f"{len(crossed)} notification(s) crossed to the client after the "
        f"session was invalidated")


def test_the_dropped_notification_is_recorded_with_its_invalidation_cause(tmp_path):
    """A drop that cannot say WHY is indistinguishable from a frame we lost.

    Observed on the core's event list, which is where the OTHER two
    NOTIFICATION_DROPPED emits already go -- following the established path
    rather than inventing a second one. OPEN QUESTION for T9, raised rather
    than decided quietly: `NOTIFICATION_DROPPED` is also in `receipts.py`'s
    frozen kind allowlist, which suggests it is meant to reach the durable
    jsonl too. If so, all three emits move together, and that is a change to
    the record's shape rather than something to slip in beside this row.
    """
    session, route, log, _out = _invalidated_route(tmp_path)
    route.pump_upstream(_notification())
    log.close()

    dropped = [e for e in session._core.events
               if e.get("kind") == "NOTIFICATION_DROPPED"]
    assert len(dropped) == 1, [e.get("kind") for e in session._core.events]
    assert dropped[0].get("reason_code") == "DESCRIPTOR_CHANGED", dropped[0]


def test_the_dropped_notification_gets_no_wire_response(tmp_path):
    """T2.R12. A notification has no id, so there is nothing to answer in.
    Refusing one on the wire would invent a response to a frame that asked for
    none."""
    _session, route, log, out = _invalidated_route(tmp_path)
    route.pump_upstream(_notification())
    log.close()

    # NOT "no error frame at all": the teardown legitimately refuses the
    # OUTSTANDING REQUEST (id 1) that was admitted before the invalidation, and
    # forbidding that would be a row asserting a different bug. What must not
    # exist is a frame answering the NOTIFICATION, and a notification has no
    # id, so an invented answer to it is one with a null id.
    answered_nothing = [json.loads(raw) for raw in out if raw
                        if json.loads(raw).get("id", "absent") is None]
    assert not answered_nothing, (
        f"a notification drop produced a null-id response: {answered_nothing}")


# ── item 2, part 2 · the drop reaches DISK by the path the product uses ──────

@pytest.mark.xfail(strict=True, reason=(
    "the core-event drain is #185 part 2 (attach_receipts -> _core_event -> "
    "jsonl) and is not on this base; STRICT so this row demands attention the "
    "moment the drain arrives, instead of quietly passing"))
def test_the_dropped_notification_reaches_the_receipt_file(tmp_path):
    """R-CLOSE-KIND-R2's shape, and the reason it has that shape.

    A previous version of this idea wrote through `receipts.Log` DIRECTLY and
    passed, which proved the Log CAN carry a field and never that the product
    DOES. ASTRA then measured the native path: `Session._emit` appends to an
    in-memory list, nothing drains it, and the field reached disk 0 times in
    20. So this row constructs NO transport of its own. It drives the product
    -- an invalidated session, a notification arriving -- and then reads the
    receipt FILE back through `proxy.receipts.verify`, which is the reader an
    operator would use.

    A receipt that exists only in memory is not a receipt. It is gone with the
    process, and #185's whole subject is a record somebody can read afterwards.
    """
    _session, route, log, _out = _invalidated_route(tmp_path)
    route.pump_upstream(_notification())
    # `verify` requires a terminal event, and the terminal is written by
    # serve.py (`log.event("SESSION_TORN_DOWN", ...)`), one layer above this
    # row. Standing in for that ONE line is not constructing the transport for
    # the field under test -- the drop has to arrive on its own, by the path the
    # product uses, or this row fails. Without it the row goes red on "the log
    # has no terminal event", which would be the harness talking, not the
    # defect.
    log.event("SESSION_TORN_DOWN")
    log.close()

    report = receipts.verify(log.path)
    assert report.ok, getattr(report, "detail", report)

    rows = _rows(log)
    dropped = [r for r in rows if r.get("kind") == "NOTIFICATION_DROPPED"]
    assert len(dropped) == 1, (
        f"the drop is not on disk: the file holds "
        f"{[r.get('kind') for r in rows]}. A receipt that exists only in the "
        f"core's in-memory list is not a receipt.")
    assert dropped[0].get("reason_code") == "DESCRIPTOR_CHANGED", dropped[0]
