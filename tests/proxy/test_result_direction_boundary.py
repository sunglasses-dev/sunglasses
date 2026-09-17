"""ASTRA's RD blockers on #168: the result direction's settlement boundary.

Four rows, one mistake in four shapes. The inspection seam ran BEFORE the pump
had taken ownership of the item, so the replacement it produced skipped every
rule the ordinary path enforces: the shape check that makes a mismatched result
a protocol fault, the record that makes a close or a cancel win, and the single
answer T6.R1 allows per id.

The rows are ASTRA's; the wiring is ours.
"""
import json
import types

import pytest

from sunglasses.proxy import pump, receipts
from sunglasses.proxy.route import Route


def wire(message):
    return (json.dumps(message, separators=(",", ":")) + "\n").encode()


def _worker_result(binding, content_bytes, finding):
    return dict(binding=dict(binding), accepted=True, status="complete",
                inspection_complete=True,
                decision="block" if finding else "allow",
                findings=[dict(rule_id="GLS-SD-001", severity="critical",
                               source="engine")] if finding else [],
                inspected_utf8_bytes=content_bytes,
                observed_content_bytes=content_bytes, elapsed_ms=0)


def _route(tmp_path, *, finding, on_scan=None):
    """A route holding one client request, with a scan we can interrupt."""
    out = []
    session = pump.Session(strict=False)
    assert session.admit_request(1, method="tools/call", origin="client")

    def scan(surface, *, channel, binding, content_bytes):
        if on_scan is not None:
            on_scan(route)
        return _worker_result(binding, content_bytes, finding)

    route = Route(session=session, log=receipts.Log(tmp_path, run_id="review", header={}),
                  upstream_write=lambda raw: None,
                  client_write=out.append, scan=scan,
                  catalog={"GLS-SD-001", "GLS-PI-001"},
                  approvals=types.SimpleNamespace(may_call=lambda *a: None,
                                                  invalidate=lambda: None))
    return route, out


def _reason_codes(out):
    codes = []
    for raw in out:
        try:
            message = json.loads(raw)
        except Exception:  # noqa: BLE001
            continue
        codes.append(message.get("error", {}).get("data", {}).get("reason_code"))
    return codes


def _answer(content=None):
    """A result with a REAL text leaf.

    An empty `content` takes the zero-leaves exit and the scan is never called,
    so a row that interrupts the scan would interrupt nothing and the original
    would cross for a reason that has nothing to do with what is under test.
    """
    return wire({"jsonrpc": "2.0", "id": 1,
                 "result": {"content": content if content is not None
                            else [{"type": "text", "text": "hello"}]}})


# ── RD07 · shape validation happens BEFORE inspection ───────────────────────

def test_RD07_a_malformed_result_is_a_protocol_fault_not_a_finding(tmp_path):
    """A result whose shape does not match the request it claims to answer is
    MALFORMED_UPSTREAM and the session ends -- T7.R1, and `deliver_response`
    already enforces it.

    The seam ran first, so a malformed result WITH a finding was inspected,
    came back PROHIBITED_CONTENT, and the session stayed open: the peer sent us
    a frame that does not answer anything and we replied as though it had,
    which also means the shape check can be skipped by attaching a finding.
    """
    route, out = _route(tmp_path, finding=True)
    # Inspectable AND shape-invalid, which took three tries to construct and
    # the wrong ones measure other branches: a bare 7 among the items is
    # UNSUPPORTED_CONTENT before anything looks at the shape, and a result with
    # no leaf takes the zero-leaves exit. This one has a real text leaf, so the
    # scan runs and produces the finding, and a second item missing its `text`
    # member, which `_shape_matches` rejects.
    route.pump_upstream(wire({"jsonrpc": "2.0", "id": 1,
                              "result": {"content": [{"type": "text",
                                                      "text": "hello"},
                                                     {"type": "text"}]}}))
    assert _reason_codes(out) == ["MALFORMED_UPSTREAM"], _reason_codes(out)
    assert route.session.closed_with() is not None, "the session stayed open"


# ── RD08 · a close during the scan wins ─────────────────────────────────────

def test_RD08_a_close_inside_the_callback_leaves_exactly_one_answer():
    """T6.R1: at most ONE response per client request.

    The replacement was yielded directly rather than through `_handoff`, so the
    close's retained refusal and the seam's replacement both reached the wire.
    Two answers for one id is the shape the whole settlement record exists to
    prevent, and here it arrived through the door added for the result
    direction.
    """
    session = pump.Session(strict=False)
    assert session.admit_request(1, method="tools/call", origin="client")
    replacement = wire({"jsonrpc": "2.0", "id": 1,
                        "error": {"code": -32070, "message": "SUNGLASSES_WITHHELD"}})

    def inspect(raw, message):
        session._close("MALFORMED_UPSTREAM", "review fault")
        return replacement, "PROHIBITED_CONTENT", "S2"

    frames = [f for f in session.read_upstream(_answer(), inspect=inspect) if f]
    assert len(frames) == 1, f"{len(frames)} answers crossed for one id"


# ── RD04 · a cancel during the scan wins, and settles as the cancel ─────────

def test_RD04_a_cancel_during_the_scan_is_the_one_answer(tmp_path):
    """T6.R5. The item was cancelled while the scan ran, so the client's one
    answer is REQUEST_CANCELLED. The finding produced a SECOND frame for the
    same id, PROHIBITED_CONTENT, because the seam settled on its own."""
    def cancel(route):
        route._cancel({"params": {"requestId": 1}})

    route, out = _route(tmp_path, finding=True, on_scan=cancel)
    route.pump_upstream(_answer())
    codes = _reason_codes(out)
    assert len(out) == 1, f"{len(out)} frames crossed for one id: {codes}"
    assert codes == ["REQUEST_CANCELLED"], codes


# ── RD03 · invalidation during the scan is checked before the yield ─────────

def test_RD03_invalidation_during_the_scan_withholds_the_original(tmp_path):
    """T5.R4. `list_changed` arriving while the scan runs means the descriptors
    moved under it, so the answer in flight is from a server nobody approved.

    The barrier was asked BEFORE the scan and never again, so an invalidation
    that landed during the scan let the original cross -- the one window where
    it matters, because the scan is the part that takes time.
    """
    def invalidate(route):
        route._invalidated = "DESCRIPTOR_CHANGED"

    route, out = _route(tmp_path, finding=False, on_scan=invalidate)
    route.pump_upstream(_answer())
    codes = _reason_codes(out)
    assert codes == ["DESCRIPTOR_CHANGED"], codes
    assert all(b'"result"' not in raw for raw in out), "the original crossed"


# ── round 3 · the barrier is asked AT THE HANDOFF, not only before the scan ──
#
# ASTRA's round-2 instrument pauses the reader ON the yield line and completes
# the action there. The rows above interrupt the SCAN, which the round-2 repair
# already covered; these interrupt the window the repair left open -- after the
# scan returned, before anything crossed. He found four shapes, and the same
# sentence explains all four: `_inspect_result` asks the release barrier once,
# before the scan, and the scan is where the time goes.


def _at_the_handoff(route, action):
    """Complete `action` while the reader is at the handoff, before it decides.

    A three-argument wrapper ON PURPOSE. `_handoff` keeps that signature and
    the gate travels on the session instead, because reviewers' controls
    substitute this method with a three-argument stub -- and a longer signature
    turns every one of them into a TypeError. Round 3's first draft did exactly
    that and broke RD10, which is an instrument failing on a change it had no
    reason to notice.
    """
    original = route.session._handoff

    def handoff(identity, raw, record_key):
        action(route)
        return original(identity, raw, record_key)

    route.session._handoff = handoff


@pytest.mark.parametrize("finding", [False, True], ids=["clean", "finding"])
def test_a_cancellation_at_the_handoff_wins(tmp_path, finding):
    """RD04b/c. The frame is in the READER's hands, not the client's.

    `Route._cancel` asked `session.expects`, which reads `_pending` only. By
    the handoff the item has moved to `_settling`, so the cancel returned
    without cancelling anything and the original crossed -- or, with a finding,
    the PROHIBITED_CONTENT refusal did. Either way the client's last word about
    a request it cancelled was an answer to it.
    """
    route, out = _route(tmp_path, finding=finding)
    _at_the_handoff(route, lambda r: r._cancel({"params": {"requestId": 1}}))
    route.pump_upstream(_answer())
    codes = _reason_codes(out)
    assert codes == ["REQUEST_CANCELLED"], codes
    assert all(b'"result"' not in raw for raw in out), "the original crossed"
    assert len([raw for raw in out if raw]) == 1, "more than one answer"


@pytest.mark.parametrize("finding", [False, True], ids=["clean", "finding"])
def test_an_invalidation_at_the_handoff_wins(tmp_path, finding):
    """RD03b/c. Same window, the other authority.

    The descriptors moved while the answer was in flight, so what is about to
    cross is from a server nobody approved. With a finding the previous head
    sent PROHIBITED_CONTENT, which reads as "we inspected this and refused it"
    when the truthful answer is that the approval it was inspected under no
    longer exists.
    """
    route, out = _route(tmp_path, finding=finding)
    _at_the_handoff(route, lambda r: setattr(r, "_invalidated",
                                             "DESCRIPTOR_CHANGED"))
    route.pump_upstream(_answer())
    codes = _reason_codes(out)
    assert codes == ["DESCRIPTOR_CHANGED"], codes
    assert all(b'"result"' not in raw for raw in out), "the original crossed"
    assert len([raw for raw in out if raw]) == 1, "more than one answer"


def test_an_item_being_answered_is_not_an_item_already_delivered(tmp_path):
    """The unit-level property under the cancel fix.

    `expects` reads `_pending`; an item mid-handoff is in `_settling`. Asking
    the wrong table is what made a live obligation look like a delivered one.
    """
    route, out = _route(tmp_path, finding=False)
    seen = {}

    def observe(r):
        seen["expects"] = r.session.expects(1, origin="client")
        seen["settling"] = r.session.is_settling(1, origin="client")

    _at_the_handoff(route, observe)
    route.pump_upstream(_answer())
    assert seen == {"expects": False, "settling": True}, seen


def test_a_close_at_the_handoff_still_wins_over_the_gate(tmp_path):
    """RD08, kept green on purpose.

    The gate runs inside the same critical section as the close check, AFTER
    it. A round that made cancellation authoritative could easily have made it
    authoritative over a torn-down session too, which would put a frame on the
    wire after the session ended.
    """
    route, out = _route(tmp_path, finding=False)

    def close_and_cancel(r):
        r._cancel({"params": {"requestId": 1}})
        r.session._close("MALFORMED_UPSTREAM", "review handoff fault")

    _at_the_handoff(route, close_and_cancel)
    route.pump_upstream(_answer())
    assert all(b'"result"' not in raw for raw in out), "the original crossed"
    assert route.session.closed_with()[0] == "MALFORMED_UPSTREAM"
