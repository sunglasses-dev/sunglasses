"""R-CLOSE-KIND: the kind has to reach the RECEIPT, not just the event list.

The behaviour rows live here rather than in the map file, because the map is
about the source and this is about what a reader gets.
"""
import json
import pathlib

import pytest

from sunglasses.proxy import pump, receipts


def wire(message):
    return (json.dumps(message, separators=(",", ":")) + "\n").encode()


def _kinds(session):
    return [event.get("cause_kind") for event in session.events
            if event["kind"] in ("TEARDOWN", "SETTLED")]


def test_two_closes_that_share_a_reason_and_a_rule_are_now_distinguishable():
    """The whole point, in one row.

    `MALFORMED_UPSTREAM`/`S5` fires at eight sites. These two are one `if`
    apart: a response for an id nobody is waiting on, and a response whose
    shape does not fit the request it claims to answer. Before this change
    their receipts were identical -- same reason, same rule, and the sentence
    that tells them apart is prose that never enters evidence.
    """
    unsolicited = pump.Session(strict=False)
    assert unsolicited.admit_request(1, method="tools/call", origin="client")
    unsolicited.deliver_response(origin="upstream", request_id=99,
                                 frame={"jsonrpc": "2.0", "id": 99,
                                        "result": {}})

    mismatched = pump.Session(strict=False)
    assert mismatched.admit_request(1, method="tools/call", origin="client")
    mismatched.deliver_response(origin="upstream", request_id=1,
                                frame={"jsonrpc": "2.0", "id": 1, "result": {}})

    assert unsolicited.closed_with() == mismatched.closed_with(), (
        "the premise of this row is that reason and rule are the SAME")
    assert "RESPONSE_NOT_PENDING" in _kinds(unsolicited), _kinds(unsolicited)
    assert "RESPONSE_SHAPE_MISMATCH" in _kinds(mismatched), _kinds(mismatched)
    assert set(_kinds(unsolicited)) != set(_kinds(mismatched))


def test_an_ordinary_settlement_carries_no_kind():
    """Null means "this cause did not come from a close", and that is the
    honest value. A name invented to avoid a null would describe a close that
    never happened."""
    session = pump.Session(strict=False)
    assert session.admit_request(1, method="tools/call", origin="client")
    session.deliver_response(
        origin="upstream", request_id=1,
        frame={"jsonrpc": "2.0", "id": 1,
               "result": {"content": [{"type": "text", "text": "hi"}]}})
    settled = [e for e in session.events if e["kind"] == "SETTLED"]
    assert settled, [e["kind"] for e in session.events]
    # PRESENT and null, not absent. `.get()` returning None is also what a
    # tree without the field at all would give, so the first draft of this row
    # passed on the old head -- a control green on the very absence it exists
    # to describe.
    assert all("cause_kind" in e and e["cause_kind"] is None
               for e in settled), settled


def test_the_kind_survives_the_trip_to_DISK(tmp_path):
    """The row that decides whether this change did anything.

    `session.events` is a list in memory; the RECEIPT is a file, and
    `receipts.Log` keeps only the fields in its own allowlist. A field missing
    from `PERMITTED_FIELDS` is dropped on the way to disk without a word, so
    every in-memory assertion above would still pass while a reader of the
    receipt learned nothing. Measured before the allowlist was extended: a
    SETTLED row written with `cause_kind` came back without it.
    """
    log = receipts.Log(tmp_path, run_id="kinds", header={})
    log.event("SETTLED", reason_code="MALFORMED_UPSTREAM", rule="S5",
              budget=None, cause_kind="RESPONSE_SHAPE_MISMATCH",
              detail="prose that must never reach evidence")
    log.close()
    rows = [json.loads(line)
            for path in sorted(p for p in tmp_path.rglob("*") if p.is_file())
            for line in path.read_text().splitlines() if line.strip()]
    settled = [row for row in rows if row.get("kind") == "SETTLED"]
    assert len(settled) == 1, rows
    assert settled[0]["cause_kind"] == "RESPONSE_SHAPE_MISMATCH"
    # And the prose still does not make it, which is the other half of the
    # bargain: a discriminator from a fixed vocabulary IN, peer-shaped text OUT.
    assert "detail" not in settled[0], settled[0]


def test_a_kind_outside_the_catalog_is_refused_not_stored():
    from sunglasses.proxy.session import Cause
    with pytest.raises(ValueError) as raised:
        Cause("MALFORMED_UPSTREAM", "S5", kind="SOMETHING_I_MADE_UP")
    assert "catalog" in str(raised.value)
