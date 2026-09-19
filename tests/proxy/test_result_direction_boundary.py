"""ASTRA's RD blockers on #168: the result direction's settlement boundary.

Four rows, one mistake in four shapes. The inspection seam ran BEFORE the pump
had taken ownership of the item, so the replacement it produced skipped every
rule the ordinary path enforces: the shape check that makes a mismatched result
a protocol fault, the record that makes a close or a cancel win, and the single
answer T6.R1 allows per id.

The rows are ASTRA's; the wiring is ours.
"""
import hashlib
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


# ── round 6 · the window after the decision, and who is still owed ──────────

def _during_the_frame_build(route, action):
    """Complete `action` while the withheld frame is being PREPARED.

    After the decision, after the authority lock has been released, and before
    the obligation is retired -- the window round 5 left open. The item is
    still in `_settling` throughout, so the route's own `_cancel` correctly
    leaves the answer to the handoff gate.

    ONCE, and bounded on its own thread, for the reasons round 5's helper
    records: the builder is re-entered when the answer changes, and an inline
    writer would self-deadlock under the mutation that takes the reader's lock.
    """
    original = route._release_frame
    seen = {"builds": 0}

    def build(request_id, reason):
        seen["builds"] += 1
        if seen["builds"] == 1:
            worker = threading.Thread(target=lambda: action(route), daemon=True)
            worker.start()
            worker.join(2)
            seen["completed"] = not worker.is_alive()
        return original(request_id, reason)

    route._release_frame = build
    return seen


@pytest.mark.parametrize("finding", [False, True], ids=["clean", "finding"])
def test_an_authority_during_the_frame_build_still_wins(tmp_path, finding):
    """XE02_frame_cancel. The epoch stopped protecting too early.

    Round 5 validated the decision under `_authority_lock` and then released
    it, and the frame is built by fallible code outside every lock. A
    cancellation accepted during that build -- including one released by the
    re-derivation lock itself -- was invisible to the retirement, which spent
    the stale `DESCRIPTOR_CHANGED` frame it already had in hand.

    The obligation is still owed at that instant; that is exactly why the item
    is retained through preparation at all. Retirement re-validates now.
    """
    route, out = _route(tmp_path, finding=finding)
    _at_the_handoff(route, lambda r: setattr(r, "_invalidated",
                                             "DESCRIPTOR_CHANGED"))
    seen = _during_the_frame_build(
        route, lambda r: r._cancel({"params": {"requestId": 1}}))
    route.pump_upstream(_answer())

    assert seen.get("completed"), "the cancellation never landed"
    assert _reason_codes(out) == ["REQUEST_CANCELLED"], _reason_codes(out)
    assert len([raw for raw in out if raw]) == 1, "more than one answer"


def test_the_retirement_re_derives_without_spending_a_gate_call(tmp_path):
    """The shape ASTRA's count forces, and the reason the policy moved.

    `XE02_rederive_writer` asserts the right answer AND exactly two gate calls.
    Count them: the first returns nothing, an invalidation lands, the discharge
    re-derives as the second, and a cancellation blocked on `_authority_lock`
    during that second call completes only once it is released. The answer
    that must reach the client therefore needs a THIRD derivation which may not
    be a third gate call.

    So `release_decision` lives on the session, where the recorded cause, the
    cancelled set, the invalidation and the epoch already live, and
    `Route._release_gate` is the adapter that keeps the name reviewer controls
    wrap. One implementation, two entry points.
    """
    route, out = _route(tmp_path, finding=False)
    session = route.session
    original = route._release_gate
    calls = []

    def gate(request_id):
        calls.append(request_id)
        reason = original(request_id)
        if len(calls) == 1:
            route._invalidated = "DESCRIPTOR_CHANGED"
        return reason

    route._release_gate = gate
    _during_the_frame_build(
        route, lambda r: r._cancel({"params": {"requestId": 1}}))
    route.pump_upstream(_answer())

    assert _reason_codes(out) == ["REQUEST_CANCELLED"], _reason_codes(out)
    assert len(calls) == 2, (
        f"the retirement spent a gate call: {len(calls)}")


def test_a_decision_that_does_not_change_is_not_re_derived_for_ever(tmp_path):
    """The loop terminates, and the first draft of it did not.

    Comparing the EPOCH rather than the decision meant every rebuild let the
    writer move the epoch again, so the answer was re-derived to the same value
    until the cap and the session closed INTERNAL_FAULT with the correct answer
    already in hand. An epoch that moved says the decision MIGHT be stale; only
    the decision says whether it is.
    """
    route, out = _route(tmp_path, finding=False)
    original = route._release_frame
    builds = []

    def build(request_id, reason):
        builds.append(reason)
        # A writer on EVERY build, which is what the reviewer's control does.
        worker = threading.Thread(
            target=lambda: route._cancel({"params": {"requestId": 1}}),
            daemon=True)
        worker.start()
        worker.join(2)
        return original(request_id, reason)

    _at_the_handoff(route, lambda r: setattr(r, "_invalidated",
                                             "DESCRIPTOR_CHANGED"))
    route._release_frame = build
    route.pump_upstream(_answer())

    assert route.session.closed_with() is None, (
        f"the session closed: {route.session.closed_with()}")
    assert _reason_codes(out) == ["REQUEST_CANCELLED"], _reason_codes(out)
    assert len(builds) == 2, f"the answer was rebuilt {len(builds)} times"


# ── round 6 · a receipt failure answers everyone still owed ─────────────────

def _fail_receipts_at(route, event):
    """Break the log at one real event, the way the reviewer's sweep does."""
    original = route.log.event
    fired = []

    def failing(kind, **fields):
        if kind == event and not fired:
            fired.append(kind)
            route.log.fail_writes(OSError(f"injected full disk at {kind}"))
        return original(kind, **fields)

    route.log.event = failing
    return fired


@pytest.mark.parametrize("event", ["SCAN_STARTED", "SCAN_RESULT",
                                   "RELEASE_AUTHORIZED"])
def test_a_receipt_failure_anywhere_answers_the_client_once(tmp_path, event):
    """XE03. The bounded refusal reached ONE path out of many.

    Round 5 paid it from `_release_frame`, so it arrived only when the frame
    BUILD failed. A failure at the scan events, at the first settlement, at the
    release authorisation or inside its fsync leaves the record already retired
    and the frame never written: the close finds nothing to retain, and
    `_release_inbound` will not release what it cannot authorise. Zero frames
    for a client still blocked on its request, on a perfectly writable sink.

    The refusal is keyed on OWNERSHIP now -- admitted and not yet answered on
    the wire -- so it is paid wherever the log dies, exactly once.
    """
    route, out = _route(tmp_path, finding=False)
    fired = _fail_receipts_at(route, event)
    route.pump_upstream(_answer())

    assert fired, f"the {event} receipt was never reached"
    assert _reason_codes(out) == ["RECEIPT_IO_ERROR"], _reason_codes(out)
    body = json.loads([raw for raw in out if raw][0])
    assert body["error"]["data"]["inspection_complete"] is False, body
    assert body["error"]["data"]["status"] == "not_run", body


def test_a_failure_recording_completion_does_not_answer_twice(tmp_path):
    """The other side of the same rule, and the reason it is keyed on
    ownership rather than on the failure.

    `WRITE_COMPLETE` is recorded AFTER the frame has crossed. The client has
    its one answer; a bounded refusal here would be a second. ASTRA names this
    as the fix to avoid, so it has a row rather than a comment.
    """
    route, out = _route(tmp_path, finding=False)
    fired = _fail_receipts_at(route, "WRITE_COMPLETE")
    route.pump_upstream(_answer())

    assert fired, "the WRITE_COMPLETE receipt was never reached"
    assert len([raw for raw in out if raw]) == 1, "the client was answered twice"
    assert b'"result"' in [raw for raw in out if raw][0], (
        "the original did not cross")


def test_every_client_still_owed_is_paid_exactly_once(tmp_path):
    """XE04. Two pending requests, one receipt failure, two answers.

    Paying only the item being handed off left the second client waiting for
    ever: the close retained its obligation and `_release_inbound` suppressed
    the retained frame on the dead log.
    """
    route, out = _route(tmp_path, finding=False)
    assert route.session.admit_request(2, method="tools/call", origin="client")
    fired = _fail_receipts_at(route, "SCAN_STARTED")
    route.pump_upstream(_answer())

    assert fired
    codes = _reason_codes(out)
    assert codes == ["RECEIPT_IO_ERROR", "RECEIPT_IO_ERROR"], codes
    answered = sorted(json.loads(raw)["id"] for raw in out if raw)
    assert answered == [1, 2], answered


def test_a_notification_receipt_failure_pays_the_pending_request(tmp_path):
    """XE05. The notification owns no id and borrows nobody's.

    A receipt failure at the notification boundary left a known pending request
    with no answer at all. The notification itself must not receive a JSON-RPC
    response -- it never had an id to put one in -- so the refusal belongs to
    the request that is still owed one.
    """
    route, out = _route(tmp_path, finding=False)
    fired = _fail_receipts_at(route, "RELEASE_AUTHORIZED")
    route.pump_upstream(wire({"jsonrpc": "2.0",
                              "method": "notifications/message",
                              "params": {"data": "ordinary notice"}}))

    assert fired
    assert _reason_codes(out) == ["RECEIPT_IO_ERROR"], _reason_codes(out)
    assert json.loads([raw for raw in out if raw][0])["id"] == 1, (
        "the refusal did not name the request that is owed one")


def test_a_locally_written_answer_is_not_paid_a_second_time(tmp_path):
    """The client-side half of the same ownership rule.

    Not every answer leaves through the release path. A cancellation, an
    admission refusal and a close answer are written straight to the client by
    `_withhold` and friends, and those ids are answered just as finally as one
    that crossed as a frame. A later receipt failure must not hand them a
    second answer.

    This row exists because the mutation that stops `_to_client` clearing the
    id SURVIVED the rest of the file: every other path clears through
    `_release_inbound`, so nothing reached the line. A control nothing reaches
    is a control that is not there.
    """
    route, out = _route(tmp_path, finding=False)
    route._cancel({"params": {"requestId": 1}})
    assert _reason_codes(out) == ["REQUEST_CANCELLED"], _reason_codes(out)

    route.log.fail_writes(OSError("injected full disk after the answer"))
    route._record("WRITE_COMPLETE", bytes=0)

    assert _reason_codes(out) == ["REQUEST_CANCELLED"], (
        f"the cancelled request was answered twice: {_reason_codes(out)}")


# ── round 7 · a superseded decision is not a settlement ────────────────────

def _receipt_rows(tmp_path):
    route_log = sorted(path for path in tmp_path.rglob("*") if path.is_file())
    return [json.loads(line) for path in route_log
            for line in path.read_text().splitlines() if line.strip()]


def test_a_re_derived_answer_settles_the_item_exactly_once(tmp_path):
    """R-168-R6a. SETTLED is the item's TERMINAL, not a note on a decision.

    Round 6 recorded inside the frame builder, and the builder repeats when
    authority moves during preparation -- so a cancellation arriving mid-build
    left `SETTLED(DESCRIPTOR_CHANGED)` behind before `SETTLED(REQUEST_CANCELLED)`.
    Two terminals for one item, while the wire correctly carried one answer and
    the core settled once. Anything that counts settlements per item -- #185's
    verify, any reader shaped like XB04 -- then disagrees with what the client
    actually got, which is the whole class of defect this lane keeps closing.

    The split: building is PURE and may repeat; recording is fallible and
    happens once, after `_retire_prepared` has established under
    `_authority_lock` that the decision can no longer move.
    """
    route, out = _route(tmp_path, finding=False)
    _at_the_handoff(route, lambda r: setattr(r, "_invalidated",
                                             "DESCRIPTOR_CHANGED"))
    seen = _during_the_frame_build(
        route, lambda r: r._cancel({"params": {"requestId": 1}}))
    route.pump_upstream(_answer())
    route.log.close()

    assert seen["builds"] == 2, (
        f"the answer was not re-derived, so this row measured nothing: {seen}")
    assert _reason_codes(out) == ["REQUEST_CANCELLED"], _reason_codes(out)

    settled = [row for row in _receipt_rows(tmp_path)
               if row.get("kind") == "SETTLED"]
    assert len(settled) == 1, (
        f"one item, {len(settled)} terminals: "
        f"{[row.get('reason_code') for row in settled]}")
    assert settled[0]["reason_code"] == "REQUEST_CANCELLED", settled
    assert settled[0]["reason_code"] == _reason_codes(out)[0], (
        "the receipt and the wire disagree about how this item ended")


def test_the_builder_writes_no_receipt_at_all(tmp_path):
    """The shape, pinned, because the row above only catches it when the
    rebuild happens. A receipt written from inside the builder is a receipt
    written once per attempt at an answer."""
    import ast
    import inspect
    import textwrap

    from sunglasses.proxy.route import Route

    tree = ast.parse(textwrap.dedent(inspect.getsource(Route._release_frame)))
    called = {ast.unparse(node.func) for node in ast.walk(tree)
              if isinstance(node, ast.Call)}
    assert "self._record" not in called, called
    assert any("_withhold_result" in name for name in called), called
    source = inspect.getsource(Route._release_frame)
    assert "record=False" in source, (
        "the builder still asks _withhold_result to record")


# ── round 8 · one terminal, the right key, and bytes that actually moved ────

def pump_key(session, request_id, origin="client"):
    return pump.key(origin, request_id)


def _settled_rows(tmp_path):
    return [row for row in _receipt_rows(tmp_path)
            if row.get("kind") == "SETTLED"]


@pytest.mark.parametrize("finding", [False, True], ids=["clean", "finding"])
def test_an_authority_answer_leaves_one_terminal_equal_to_the_wire(
        tmp_path, finding):
    """XS02/XS17. Round 7 made the HANDOFF the single recorder for the
    authority answer, and left two other recorders standing.

    The inspection seam builds its replacement through `_withhold_result`,
    which recorded -- so a finding, or an invalidation seen before the scan,
    wrote a terminal that the handoff then superseded. The receipt named
    PROHIBITED_CONTENT while the wire said REQUEST_CANCELLED: two terminals for
    one item, disagreeing with each other and with the client.
    """
    route, out = _route(tmp_path, finding=finding)
    route._invalidated = "DESCRIPTOR_CHANGED"
    route.pump_upstream(_answer())
    route.log.close()

    settled = _settled_rows(tmp_path)
    assert len(settled) == 1, [row.get("reason_code") for row in settled]
    assert settled[0]["reason_code"] == _reason_codes(out)[0], (
        "the receipt and the wire disagree about how this item ended")


def test_a_clean_crossing_records_that_it_ended(tmp_path):
    """XS13. The other half of "one terminal": not zero.

    A crossing with no authority replacement wrote NO terminal at all, so an
    ordinary answer reached the client with nothing in the receipt saying the
    item had ended. `_handoff` calls itself the single point where an
    obligation ends; that is where the terminal belongs, taken from the cause
    the item was actually settled with.
    """
    route, out = _route(tmp_path, finding=False)
    route.pump_upstream(_answer())
    route.log.close()

    settled = _settled_rows(tmp_path)
    assert len(settled) == 1, [row.get("reason_code") for row in settled]
    assert settled[0]["reason_code"] == "CLEAN", settled


def test_two_ids_python_calls_equal_are_two_clients(tmp_path):
    """XS06/XS14. `{1, 1.0}` is `{1}`.

    The session keys its own tables on `key(origin, request_id)`, which carries
    the JSON TYPE, precisely because 1 and 1.0 are different ids to a peer and
    the same key to Python. My unanswered set held bare request ids, so two
    waiting clients were recorded as one and the second was never answered.
    Third time in two days that I used a weaker key than the session's own.
    """
    route, out = _route(tmp_path, finding=False)
    assert route.session.admit_request(1.0, method="tools/call",
                                       origin="client")
    fired = _fail_receipts_at(route, "SCAN_STARTED")
    route.pump_upstream(_answer())

    assert fired
    answered = sorted((type(json.loads(raw)["id"]).__name__,
                       json.loads(raw)["id"]) for raw in out if raw)
    assert answered == [("float", 1.0), ("int", 1)], answered


def test_a_null_json_id_is_answered_once(tmp_path):
    """XS08. A JSON-RPC null id is a real id, and my guard skipped it.

    `_to_client` cleared the answered id only when it was `is not None` -- a
    guard written to skip notifications, which also skipped a legitimate null
    id. So a null-id request answered locally was paid a SECOND bounded refusal
    when the log died. A notification has no `id` KEY at all, which is the
    distinction that actually separates them.
    """
    route, out = _route(tmp_path, finding=False)
    assert route.session.admit_request(None, method="tools/call",
                                       origin="client")
    route._cancel({"params": {"requestId": None}})
    route.log.fail_writes(OSError("injected after the local answer"))
    route._record("SCAN_STARTED")

    ids = [json.loads(raw).get("id") for raw in out if raw]
    assert ids.count(None) == 1, f"the null id was answered {ids.count(None)} times"


def test_a_receipt_failure_during_a_release_does_not_answer_twice(tmp_path):
    """XS15/XS16. The window between committing to a release and clearing it.

    The id was cleared AFTER the write, so a receipt failure landing while the
    authorisation was in flight found the id still owed, paid it, and then the
    original crossed as well: two answers for one request, with the sink
    perfectly writable. Delivery is taken BEFORE the authorisation now, and
    given back only if the bytes never moved.
    """
    route, out = _route(tmp_path, finding=False)

    # THE AUTHORISATION MUST SUCCEED, or this measures nothing. Failing the log
    # before it means the release never happens and one frame is trivially
    # true: the first draft of this row did exactly that and passed on the
    # defect. The failure lands while the authorised bytes are on their way.
    original_write = route.client_write
    fired = []

    def client_write(raw):
        if not fired:
            fired.append(True)
            route.log.fail_writes(OSError("injected mid-release"))
            route._record("SCAN_STARTED")
        return original_write(raw)

    route.client_write = client_write
    route.pump_upstream(_answer())
    assert fired, "the release never reached the sink"

    assert len([raw for raw in out if raw]) == 1, (
        f"one request, {len([raw for raw in out if raw])} answers")


def test_a_give_back_never_resurrects_an_answered_id(tmp_path):
    """The half I got wrong while fixing the half above.

    Taking delivery early needs a give-back when the authorisation fails --
    otherwise the one path that legitimately has no frame to show is the one
    nobody answers. But the give-back resurrected ids whose bytes HAD moved:
    the payer wrote a bounded refusal straight to the sink, the close then
    drained a retained refusal for the same id whose authorisation failed, the
    id went back on the owed list and was answered a second time.

    Taking is reversible. Confirming is not.
    """
    route, out = _route(tmp_path, finding=False)
    assert route.session.admit_request(1.0, method="tools/call",
                                       origin="client")
    fired = _fail_receipts_at(route, "WRITE_COMPLETE")
    route.pump_upstream(_answer())

    assert fired
    ids = [json.loads(raw).get("id") for raw in out if raw]
    assert len(ids) == len(set(map(repr, ids))), f"an id was answered twice: {ids}"


# ── round 9 · a table that outlives its correlation carries the generation ──

def test_every_spanning_table_is_keyed_by_the_token():
    """A READING AID, NOT A PROOF, and the difference is on the record.

    ASTRA defeated the sibling of this row on #179 with two reachable mutants
    that satisfy its source pattern and still break the behaviour -- the
    behavioural suite rejected both, which is where the real guarantee lives.
    So this row is NOT class-wide proof and must not be described as one. It is
    a cheap reading of the source that catches the careless case early; the
    inventory below is the part that actually holds each API to the property.

    Four rounds, one mistake, four tables: `_claimed[identity]` on #179,
    `_unanswered` by bare id, a token compared one element at a time, and now
    `_unanswered`/`_answered_final` by identity. Each time I repaired the
    instance the reviewer drove.

    The rule is sharper than "always use the token", and the sharp form is what
    makes it checkable:

      a table describing the LIVE correlation may be keyed by IDENTITY --
      admission refuses an id already pending or settling, so only one
      generation is ever live and the identity cannot be ambiguous;

      a table whose entries OUTLIVE the correlation must carry the GENERATION,
      because its entries span generations by construction and an identity key
      lets a finished generation speak for a live one.

    This reads the source and holds every spanning table to the second half.
    """
    import ast
    import collections
    import inspect
    import textwrap

    spanning = {
        "_unanswered": "owed until a frame reaches the sink, after retirement",
        "_answered_final": "remembers an answer that already moved, for ever",
    }
    token_keys = {"token", "core_key", "self._core_key(identity)", "owed",
                  "reserved", "observed"}

    writes = collections.defaultdict(set)
    for module in (pump,):
        tree = ast.parse(textwrap.dedent(inspect.getsource(module)))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in ("add", "discard") and node.args \
                    and isinstance(node.func.value, ast.Attribute):
                writes[node.func.value.attr].add(ast.unparse(node.args[0]))

    offenders = {}
    for name, why in spanning.items():
        keys = writes.get(name, set())
        assert keys, f"{name} is never written; this row has stopped reading it"
        stray = sorted(k for k in keys if k not in token_keys)
        if stray:
            offenders[name] = (stray, why)
    assert not offenders, (
        f"these tables outlive the correlation they describe and must carry "
        f"the generation: {offenders}")


def test_two_generations_of_one_id_are_two_obligations(tmp_path):
    """XU02. A finished generation spoke for a live one.

    `_unanswered` and `_answered_final` were keyed `(origin, id)`. Admission
    bumps the generation and adds the identity but never removes the OLD
    identity from the final marker, so a reused completed id met a failed
    release like this: the take removed the second obligation, and `owe_again`
    found the first generation's marker and refused to restore it. Two admitted
    requests, one response.
    """
    route, out = _route(tmp_path, finding=False)
    session = route.session
    first = session._core_key(pump_key(session, 1))
    session.answered_on_the_wire(first, final=True)      # generation 1, answered
    # AND COMPLETED, because admission refuses an id that is still pending --
    # which is exactly why a table describing the live correlation may key on
    # the identity, and why one that outlives it may not.
    session.settle_from("client", 1, "CLEAN", "S1")

    assert session.admit_request(1, method="tools/call", origin="client")
    second = session._core_key(pump_key(session, 1))
    assert first != second, "the second admission reserved no generation"

    session.answered_on_the_wire(second)                 # taken, not confirmed
    session.owe_again(second)                            # the release failed

    assert second in session.unanswered_clients(), (
        "a finished generation suppressed the live one's restitution")
    assert first not in session.unanswered_clients()


def test_a_late_confirmation_names_the_generation_it_confirms(tmp_path):
    """XU13. Clearing at admission is not enough, because of the ordering.

    A late confirmation for the FIRST generation arrives after the second has
    been admitted. Keyed by identity it discarded the new generation's
    obligation and the new request was never answered.
    """
    route, out = _route(tmp_path, finding=False)
    session = route.session
    first = session._core_key(pump_key(session, 1))
    session.settle_from("client", 1, "CLEAN", "S1")      # generation 1 completes
    assert session.admit_request(1, method="tools/call", origin="client")
    second = session._core_key(pump_key(session, 1))
    assert first != second

    session.answered_on_the_wire(first, final=True)      # the late confirmation

    assert second in session.unanswered_clients(), (
        "a late confirmation for an older attempt discharged a live one")


def test_the_payer_takes_its_work_and_never_snapshots_it(tmp_path):
    """XU12. A snapshot is not a claim.

    The payer read the whole outstanding list and marked each entry afterwards,
    so a REAL answer could land while it was paused holding a stale copy -- and
    the payer paid the same id again. `_paying` never helped: it prevents
    recursion, not a race.

    THE ORDERING IS THE REVIEWER'S AND MY FIRST DRAFT HAD IT BACKWARDS. Starting
    the payer first and cancelling during its pause proves nothing, because the
    cancellation's own receipt dies on the same failed log and it never reaches
    the client -- one frame, and the row passed on the defect. The cancellation
    has to be ALREADY MID-WRITE, with the payer starting from inside it.
    """
    route, out = _route(tmp_path, finding=False)
    session = route.session
    ready, failures = threading.Event(), []
    local = route._to_client

    def payer():
        try:
            route.log.fail_writes(OSError("injected"))
            route._record("SCAN_STARTED")
        except Exception as error:            # noqa: BLE001
            failures.append(type(error).__name__)

    def emit(body):
        worker = threading.Thread(target=payer, daemon=True)
        worker.start()
        assert ready.wait(3) or True
        local(body)                            # the real answer reaches the sink
        worker.join(3)
        assert not worker.is_alive(), "the payer never finished"

    route._to_client = emit
    ready.set()
    route._cancel({"params": {"requestId": 1}})

    assert not failures, failures
    answers = [raw for raw in out if raw]
    assert len(answers) == 1, (
        f"one request, {len(answers)} answers: "
        f"{[json.loads(a).get('error', {}).get('data', {}).get('reason_code') for a in answers]}")


def test_a_retained_refusal_records_that_the_item_ended(tmp_path):
    """XU15. Round 8 made the handoff the single recorder and the DRAIN does
    not pass through it, so a refusal the close retained crossed with nothing
    in the receipt saying the item had ended.

    Pre-existing before round 8 as well -- measured on `bb7607b` and `07c5c67`
    -- and fixed here because it is round 8's own principle in the one path
    that only runs when something has already gone wrong.
    """
    route, out = _route(tmp_path, finding=False)
    route.session._close("INTERNAL_FAULT", "a teardown", rule="S3")
    route.pump_upstream(b"")
    route.log.close()

    settled = _settled_rows(tmp_path)
    assert len([raw for raw in out if raw]) == 1, "the client was not answered"
    assert len(settled) == 1, (
        f"the retained refusal left {len(settled)} terminals")


def test_a_payer_whose_write_fails_gives_the_obligation_back(tmp_path):
    """Taking is reversible until the bytes move, in the payer as everywhere.

    The payer takes an obligation and then writes. If that write raises, the
    obligation was claimed and NOT discharged -- marking it answered at the
    moment of taking made the claim permanent and the client was owed an answer
    nobody held any longer.
    """
    route, out = _route(tmp_path, finding=False)
    session = route.session
    owed = session._core_key(pump_key(session, 1))
    assert owed in session.unanswered_clients()

    def refuse(raw):
        raise OSError("the client sink is gone")

    route.client_write = refuse
    route.log.fail_writes(OSError("injected"))
    try:
        route._record("SCAN_STARTED")
    except OSError:
        pass

    assert owed in session.unanswered_clients(), (
        "the payer kept an obligation it never discharged")


# ── the entry-point inventory, behavioural ─────────────────────────────────

#: Every session API that accepts an attempt token on this branch, with what a
#: FOREIGN token must not be able to do through it. Listed explicitly because a
#: source pattern can be satisfied while the behaviour is broken -- ASTRA
#: demonstrated exactly that against the structural row above -- so each entry
#: here is driven, not read.
# MERGE, #168 r9 onto #179. The six below arrived with #179 and this row is
# what stopped them arriving silently: it failed the moment the trees met,
# naming every one. Each is driven with a foreign token in the behavioural row
# under it, across all three identity dimensions -- which is the point, because
# the STRUCTURAL row that used to sit beside this was defeated by two reachable
# mutants and is not proof of anything.
TOKEN_ENTRY_POINTS = ("take_obligation", "answered_on_the_wire", "owe_again",
                      "take_delivery", "_take_delivery",
                      "claim_for_local_answer", "settle_attempt",
                      "settle_from", "cancel", "commit_local_cause")


def test_the_token_entry_point_inventory_is_complete():
    """The list is checked against the source, so a new token API cannot be
    added without either appearing here or failing this row."""
    import inspect

    taking = {name for name, member in inspect.getmembers(pump.Session,
                                                          inspect.isfunction)
              if not name.startswith("__")
              and "token" in inspect.signature(member).parameters}
    # `take_next_unanswered` hands a token OUT rather than accepting one.
    taking.discard("take_next_unanswered")
    missing = taking - set(TOKEN_ENTRY_POINTS)
    assert not missing, (
        f"these accept a token and are not in the inventory: {sorted(missing)}. "
        f"Add them with a behavioural row for a foreign token.")


@pytest.mark.parametrize("dimension", ["another id", "another JSON type",
                                       "another origin", "another generation"])
def test_a_foreign_token_moves_nothing_through_any_entry_point(tmp_path,
                                                               dimension):
    """Three identity dimensions, every listed API, driven rather than read.

    A token is (origin, JSON id type, id, generation). Each dimension is a way
    for a token to belong to a different item while still looking plausible,
    and each entry point is asked to leave BOTH items exactly as they were.
    """
    session = pump.Session()
    assert session.admit_request(1, method="tools/call", origin="client")
    mine = session._core_key(pump_key(session, 1))

    if dimension == "another id":
        assert session.admit_request(2, method="ping", origin="client")
        foreign = session._core_key(pump_key(session, 2))
    elif dimension == "another JSON type":
        assert session.admit_request(1.0, method="ping", origin="client")
        foreign = session._core_key(pump_key(session, 1.0))
    elif dimension == "another origin":
        assert session.admit_request(1, method="ping", origin="upstream")
        foreign = session._core_key(pump.key("upstream", 1))
    else:
        # ANOTHER GENERATION, and the three identity dimensions above do not
        # reach it. `settle_from` and `cancel` are keyed on (origin, id) with
        # the token as the AUTHORITY, so a token from another id or origin
        # never pointed at my item in the first place and their mutants
        # survived every row above -- measured, not guessed. The defect they
        # are actually about is a STALE token for the SAME id: #179 r7's
        # `settle_from` compared one element of a token and let an older
        # attempt settle the generation that replaced it.
        #
        # So here the stale token is the foreign one and the LIVE generation
        # is mine.
        foreign = mine
        session.settle_attempt(foreign, "UNINSPECTED_METHOD", "S1")
        assert session.admit_request(1, method="tools/call", origin="client")
        mine = session._core_key(pump_key(session, 1))
    assert foreign != mine, dimension

    before_owed = sorted(map(str, session._core.owed()))
    before_unanswered = sorted(map(str, session.unanswered_clients()))

    # Taking a foreign token must not take MINE.
    session.take_obligation(foreign)
    assert mine in session.unanswered_clients(), (
        f"{dimension}: take_obligation moved another item's obligation")
    # ...and having taken the foreign one, mine is still answerable.
    session.answered_on_the_wire(foreign, final=True)
    assert mine in session.unanswered_clients(), (
        f"{dimension}: a foreign confirmation discharged mine")
    session.owe_again(foreign)
    assert sorted(map(str, session._core.owed())) == before_owed, (
        f"{dimension}: a foreign token changed the core debt")

    # ── #179's six, each asked about the table IT governs ──────────────────
    #
    # The first version of this block asserted `mine in unanswered_clients()`
    # after every call, and five of the six mutants SURVIVED it: these APIs do
    # not touch `_unanswered`, they touch `_pending`, `_delivering` and the
    # core's debt. A row that observes the wrong table runs without being able
    # to fail, which is the shape ASTRA rejected on #179 r8. Proven by
    # warroom/r168-followups/inventory_rows_mutation_proof.py: one
    # generation-only mutant per API, each now killed by assertion.
    #
    # These are reads, not calls that consume state, so the sequence below
    # cannot make a later assertion vacuous.
    foreign_id = foreign[2]
    foreign_origin = foreign[0]
    my_identity = mine[:3]

    # `claim_for_local_answer` pops MY identity out of `_pending` if it accepts
    # a foreign token as mine.
    session.claim_for_local_answer(foreign)
    assert my_identity in session._pending, (
        f"{dimension}: claim_for_local_answer claimed another item's request")

    # `take_delivery`/`_take_delivery` add to `_delivering`.
    assert session.take_delivery(foreign) in (True, False)
    session._take_delivery(foreign)
    assert mine not in session._delivering, (
        f"{dimension}: take_delivery took delivery of MY answer")

    # `settle_attempt` settles in the core.
    session.settle_attempt(foreign, "UNINSPECTED_METHOD", "S1")
    assert mine in session._core.owed(), (
        f"{dimension}: settle_attempt with a foreign token settled MY item")
    assert mine in session.unanswered_clients(), (
        f"{dimension}: settle_attempt discharged MY obligation")

    # `settle_from` settles by origin and id, with the token as the authority.
    session.settle_from(foreign_origin, foreign_id, "UNINSPECTED_METHOD", "S1",
                        token=foreign)
    assert mine in session._core.owed(), (
        f"{dimension}: settle_from settled MY item")

    # `commit_local_cause` (R-CLOSE-KIND-R3) records how an answer ends before
    # its bytes move, so a foreign token must not commit a cause for my item --
    # that would make a close settle MINE with somebody else's reason.
    session.commit_local_cause(foreign, "UNINSPECTED_METHOD", "S1")
    assert mine not in session._committed_cause, (
        f"{dimension}: commit_local_cause committed a cause for MY item")

    # `cancel` retires an id for the rest of the session.
    session.cancel(foreign_id, origin=foreign_origin, token=foreign)
    assert mine in session._core.owed(), (
        f"{dimension}: cancel cancelled MY item")
    assert my_identity not in getattr(session, "_tombstones", {}), (
        f"{dimension}: cancel tombstoned MY id")

    # The ordinary follow-up still works for the item that was never involved.
    assert session.take_obligation(mine), (
        f"{dimension}: my own obligation was no longer takeable")

    # `owe_again` RESTORES an obligation, so its foreign-token question can only
    # be asked once mine has been taken. The original row asked whether the CORE
    # DEBT moved, which `owe_again` does not touch at all -- so it ran without
    # being able to fail, and both mutant shapes survived it. Found by deriving
    # the API list from the tree instead of hardcoding it, which brought the
    # three oldest entries back under the harness.
    assert mine not in session.unanswered_clients(), (
        f"{dimension}: taking my obligation did not clear it")
    session.owe_again(foreign)
    assert mine not in session.unanswered_clients(), (
        f"{dimension}: owe_again with a foreign token restored MY obligation")


# ── MERGE ROUND · the inbound release receipt names WHAT IT ANSWERED ─────────

def test_the_inbound_release_receipt_names_the_generation_it_answered(tmp_path):
    """T9's ruling on the merge round: `_release_inbound` hashed the literal
    marker "inbound", so the one receipt whose job is to say what a release
    answered named nothing at all -- the id-only key with no id in it.

    The reader holds the obligation token (`obligation_of_last_yield`), so the
    receipt carries it. R-168-R6a: the receipt equals the wire.
    """
    route, out = _route(tmp_path, finding=False)

    owed = list(route.session.unanswered_clients())
    assert len(owed) == 1, owed
    owed = owed[0]

    route.pump_upstream(_answer())
    route.log.close()

    rows = [json.loads(line) for line in
            route.log.path.read_text().splitlines() if line.strip()]
    authorised = [r for r in rows if r.get("kind") == "RELEASE_AUTHORIZED"]
    assert len(authorised) == 1, [r.get("kind") for r in rows]

    def token_of(value):
        return hashlib.sha256(repr(value).encode()).hexdigest()[:16]

    assert authorised[0]["id_token"] == token_of(owed), (
        "the release receipt does not name the obligation it discharged")

    # The two ways it could be wrong and still look like a token.
    assert authorised[0]["id_token"] != token_of("inbound"), (
        "the receipt is still hashing the bare marker")
    later_generation = owed[:-1] + (owed[-1] + 1,)
    assert authorised[0]["id_token"] != token_of(later_generation), (
        "the receipt does not distinguish generations of one id, which is the "
        "id-only key this whole lane exists to remove")
