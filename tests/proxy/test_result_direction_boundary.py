"""ASTRA's RD blockers on #168: the result direction's settlement boundary.

Four rows, one mistake in four shapes. The inspection seam ran BEFORE the pump
had taken ownership of the item, so the replacement it produced skipped every
rule the ordinary path enforces: the shape check that makes a mismatched result
a protocol fault, the record that makes a close or a cancel win, and the single
answer T6.R1 allows per id.

The rows are ASTRA's; the wiring is ours.
"""
import json
import threading
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


# ── round 4 · one ownership protocol, and what it is allowed to touch ────────

def test_a_recorded_fault_is_terminal_and_a_cancel_cannot_overwrite_it(tmp_path):
    """XB04. T4.R4 Rule A.

    An invalid worker completion settles SCAN_EXCEPTION before the handoff.
    Round 3's gate saw only the id, so a cancellation completing afterwards
    replaced that frame with REQUEST_CANCELLED while the core kept
    SCAN_EXCEPTION: the client's answer and the receipt disagreed about what
    happened. Rule B lets a HOLD beat a normal completion; it does not let one
    beat a recorded fault.
    """
    route, out = _route(tmp_path, finding=False)
    route.scan = lambda surface, **kw: {}          # an invalid completion
    _at_the_handoff(route, lambda r: r._cancel({"params": {"requestId": 1}}))
    route.pump_upstream(_answer())
    assert _reason_codes(out) == ["SCAN_EXCEPTION"], _reason_codes(out)


def test_an_authority_writer_completes_while_the_decision_runs(tmp_path):
    """The property that decides which lock the writers use. XG01's shape.

    A GUARD, NOT A RED-FIRST ROW. It exists to stop the WRONG FIX -- putting
    the authority writers under the settlement owner -- which was measured
    before it was written: it turns four of six XB03 rows into "action
    incomplete", the writer timing out on a lock the parked reader holds.

    THE PREVIOUS VERSION OF THIS ROW DID NOT MEASURE THAT. It completed the
    cancellation in a wrapper around `_handoff`, BEFORE the original ran, so
    its `with session._settlement: pass` had already exited and no reader was
    parked anywhere. ASTRA mutated `accept_cancellation` to take `_settlement`
    before `_authority_lock` -- the exact wrong fix this row is named after --
    and the row passed 0/1. A guard that would survive the thing it guards
    against is a guard that measures itself.

    So the writer is driven from INSIDE the decision, with the settlement owner
    provably held, and it has to finish there. That is what the reviewer's
    XG01 does and it is the shape that goes red on the mutation.
    """
    route, out = _route(tmp_path, finding=False)
    session = route.session
    original = route._release_gate
    finished = threading.Event()
    seen = {}

    def gate(request_id):
        seen["owner_held"] = session._settlement.locked()
        worker = threading.Thread(
            target=lambda: (route._cancel({"params": {"requestId": 1}}),
                            finished.set()))
        worker.start()
        seen["completed_under_owner"] = finished.wait(1)
        worker.join(2)
        return original(request_id)

    route._release_gate = gate
    route.pump_upstream(_answer())
    assert seen.get("owner_held"), (
        "the decision did not run under the settlement owner, so this row "
        "proves nothing about writers racing a parked reader")
    assert seen.get("completed_under_owner"), (
        "the cancellation could not complete while the reader held the "
        "settlement owner; the writers are waiting on the reader's lock")


# ── round 5 · the window between the decision and the discharge ─────────────

def _after_the_decision(route, action):
    """Complete `action` AFTER the gate decided and BEFORE the discharge.

    The window round 4 said did not exist. The reader is inside the settlement
    owner, the decision has been taken from authority it has already stopped
    holding, and the record has not been retired yet -- so the item is still
    owed and an authority landing here is not late.

    ON ITS OWN THREAD, BOUNDED, and that is not decoration. Called inline it
    runs on the READER's thread, which already holds the settlement owner, so
    the wrong fix this round rejects -- an authority writer that takes that
    same owner -- turns this row into a self-deadlock and the whole file hangs.
    A hang is not a kill: it reports the same way whether the property broke or
    the harness did, which is the failure ASTRA's XG01 was careful to avoid.
    Bounded and reported, the same mutation fails this row with a sentence.

    ONCE, and the first draft of this helper is the reason it says so. The
    discharge RE-ENTERS the decision when the epoch moved, and that second call
    runs while the reader holds `_authority_lock` -- so an unguarded wrapper
    fired again there and its writer blocked on the exclusion that makes the
    re-derivation atomic. The row then reported "the authority could not
    complete", which is true of the second firing and says nothing about the
    window under test. ASTRA's XD01 carries the same guard (`not fired`).

    Returns a dict the row asserts on: `completed` is False when the writer
    could not finish while the reader held the owner, and `calls` counts how
    many times the decision was taken.
    """
    original = route._release_gate
    seen = {"calls": 0}

    def gate(request_id):
        seen["calls"] += 1
        reason = original(request_id)
        if seen["calls"] > 1:
            return reason
        worker = threading.Thread(target=lambda: action(route), daemon=True)
        worker.start()
        worker.join(2)
        seen["completed"] = not worker.is_alive()
        return reason

    route._release_gate = gate
    return seen


@pytest.mark.parametrize("finding", [False, True], ids=["clean", "finding"])
@pytest.mark.parametrize("action", ["cancel", "invalidate", "both"])
def test_an_authority_after_the_decision_still_wins(tmp_path, action, finding):
    """XD01. ADJACENT LINES ARE NOT ATOMICITY.

    Round 4 removed the epoch and said so in `authority_state`: the decision is
    taken on the line before the discharge, so "nothing can move between
    them". Nothing needs to move far. The reader releases `_authority_lock`
    when the decision returns and takes only the settlement owner, which no
    writer needs -- so a cancellation completing between those two lines
    completes, and on that head the original crossed anyway. Six ways, zero
    harness errors.

    What closes it is not a shorter gap: it is a stamp. The decision records
    the epoch it read, and the discharge refuses to spend one derived from an
    older epoch and re-derives instead, holding the lock across both.
    """
    route, out = _route(tmp_path, finding=finding)

    def authority(r):
        if action in ("invalidate", "both"):
            r._invalidated = "DESCRIPTOR_CHANGED"
        if action in ("cancel", "both"):
            r._cancel({"params": {"requestId": 1}})

    seen = _after_the_decision(route, authority)
    route.pump_upstream(_answer())
    assert seen.get("completed"), (
        "the authority could not complete while the reader held the "
        "settlement owner, so this row measured the lock and not the window")
    expected = ("REQUEST_CANCELLED" if action in ("cancel", "both")
                else "DESCRIPTOR_CHANGED")
    assert _reason_codes(out) == [expected], _reason_codes(out)
    assert all(b'"result"' not in raw for raw in out), "the original crossed"
    assert len([raw for raw in out if raw]) == 1, "more than one answer"


def test_the_decision_is_re_derived_only_when_the_epoch_moved(tmp_path):
    """The mechanism itself, counted.

    The stamp is taken at the READ, not before the call, and that is what keeps
    the re-derivation rare enough to be countable: a writer that lands before
    the decision reads authority is already in the epoch that decision saw, so
    there is nothing stale to re-derive. A writer that lands after it moves the
    epoch and the decision is taken again.

    Counting matters beyond tidiness. The reviewer's XG01 drives its writer
    INTO the decision and asserts on exactly one pass through it; a re-derive
    keyed on "did the epoch change at all" fires there too and turns that
    control into an instrument failure.
    """
    route, out = _route(tmp_path, finding=False)
    quiet = _after_the_decision(route, lambda r: None)
    route.pump_upstream(_answer())
    assert quiet["calls"] == 1, "nothing moved, so nothing needed re-deriving"

    route, out = _route(tmp_path, finding=False)
    moved = _after_the_decision(route,
                                lambda r: r._cancel({"params": {"requestId": 1}}))
    route.pump_upstream(_answer())
    assert moved["calls"] == 2, "the stale decision was spent, not re-derived"
    assert _reason_codes(out) == ["REQUEST_CANCELLED"], _reason_codes(out)


def test_a_recorded_fault_survives_an_authority_after_the_decision(tmp_path):
    """XD02. The re-derivation must not smuggle Rule A out of the round.

    Re-deriving is re-asking the SAME question, through the same callback, so
    an earlier recorded S3 fault still outranks a cancellation that arrives
    afterwards. Deriving the reason a second way -- in the session, from the
    authority it holds -- would answer REQUEST_CANCELLED here while the receipt
    kept SCAN_EXCEPTION, which is the disagreement XB04 exists to prevent.
    """
    route, out = _route(tmp_path, finding=False)
    route.scan = lambda surface, **kw: {}          # an invalid completion
    seen = _after_the_decision(route,
                               lambda r: r._cancel({"params": {"requestId": 1}}))
    route.pump_upstream(_answer())
    assert seen.get("completed"), "the cancellation never landed"
    assert _reason_codes(out) == ["SCAN_EXCEPTION"], _reason_codes(out)


def test_a_receipt_failure_at_the_handoff_still_answers_the_client(tmp_path):
    """XD03. XB06 PASSING MEANT NO DEADLOCK, NOT ONE ANSWER DELIVERED.

    Round 3 deadlocked here and round 4 moved the frame builder out, which
    fixed the liveness and lost the answer: the record was retired before the
    fallible write, the failed receipt closed the session, the close found
    nothing owed to retain, and `_release_inbound` refused to release a frame
    it could not authorise. The client got ZERO frames for a request it is
    still blocked on -- which is worse than the deadlock, because nothing
    reports it.

    Two halves, and both are needed. The obligation is put back before the
    frame is built, so a close that lands during the build has a debt to
    record; and the frame's owner sends the bounded RECEIPT_IO_ERROR itself,
    because it is the only party that still knows whose answer it was.
    """
    route, out = _route(tmp_path, finding=False)
    original = route.session._handoff

    def handoff(identity, raw, record_key):
        route._invalidated = "DESCRIPTOR_CHANGED"
        route.log.fail_writes(OSError("injected full disk at the handoff"))
        return original(identity, raw, record_key)

    route.session._handoff = handoff
    done = threading.Event()
    worker = threading.Thread(target=lambda: (route.pump_upstream(_answer()),
                                              done.set()), daemon=True)
    worker.start()
    assert done.wait(5), "the reader never finished; the receipt failure hung"
    assert _reason_codes(out) == ["RECEIPT_IO_ERROR"], _reason_codes(out)
    assert all(b'"result"' not in raw for raw in out), "the original crossed"
    assert route.session.closed_with()[0] == "RECEIPT_IO_ERROR"


def test_a_close_during_the_frame_build_pays_the_debt_exactly_once(tmp_path):
    """The other half of the retained obligation, on a HEALTHY log.

    The frame is built outside the settlement owner, so a close can complete
    while it is being built. Because the record is still owed at that moment
    the close records the debt and pays it on the way out -- and the reader,
    told it no longer owns the record, hands over nothing. Retiring before the
    build loses the answer; delivering afterwards anyway makes two.
    """
    route, out = _route(tmp_path, finding=False)
    session = route.session
    original = route._release_frame

    def build(request_id, reason):
        frame = original(request_id, reason)
        session._close("MALFORMED_UPSTREAM", "close racing the frame build")
        return frame

    route._release_frame = build
    _at_the_handoff(route, lambda r: setattr(r, "_invalidated",
                                             "DESCRIPTOR_CHANGED"))
    route.pump_upstream(_answer())
    assert len([raw for raw in out if raw]) == 1, "more than one answer"
    assert _reason_codes(out) == ["MALFORMED_UPSTREAM"], _reason_codes(out)


def test_nothing_under_the_discharge_lock_calls_into_the_route():
    """XB06, as a property of the SOURCE rather than of one timing.

    The frame builder writes a receipt, a failed write answers by calling
    `Session._close`, and `_close` takes the settlement lock the reader holds
    while it decides. Round 3 called the builder inside that block and the
    reviewer reached the deadlock with the log's fail-writes seam. A timing row
    can only catch it when the timing repeats; this catches the shape.
    """
    import ast
    import inspect
    import textwrap

    from sunglasses.proxy import pump

    # `textwrap.dedent` because `getsource` of a METHOD keeps its class
    # indentation, and `ast.parse` refuses that with IndentationError -- the
    # first draft of this row failed on its own instrument rather than on the
    # code it reads.
    tree = ast.parse(textwrap.dedent(inspect.getsource(pump.Session._handoff)))
    inside = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.With):
            continue
        if not any("_settlement" in ast.unparse(item.context_expr)
                   for item in node.items):
            continue
        for call in ast.walk(node):
            if isinstance(call, ast.Call):
                inside.append(ast.unparse(call.func))
    assert "self._handoff_frame" not in inside, (
        f"the frame builder is called under the discharge lock: {inside}")
    assert "self._handoff_decide" in inside, (
        f"the DECISION must be taken under the lock, or a close racing it is "
        f"not blocked by the owner (XC01): {inside}")
