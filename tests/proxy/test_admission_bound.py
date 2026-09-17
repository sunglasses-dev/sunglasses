"""T8.R6, the admission bound, as its own subject.

The contract table says `in-flight held messages + pending forwarded requests
(outstanding correlations) / queued bytes | 8 / 16 MiB | S3 OVERLOADED on the
NEW item per T6.R7; held items never dropped`. `bounds.check_admission` has
implemented both halves since it was written and NOTHING ASKED IT: the pump
admitted a ninth correlation and a request behind a full write queue, so the
row was a table entry rather than a bound.

These rows arrived in the result-direction PR because that is where the work
happened. ASTRA's RD09 measured the change there and read it as a regression --
the base admits nine, the candidate admits eight -- which is the base being
unbounded rather than the candidate being wrong. T9 ruled it out of that PR and
into this one, where the contract row is the subject and can be reviewed as
one, and where "the body equals the delta" is true by construction.

The queued-byte half of the same row is NOT here: it reads `queued_bytes`, an
attribute the write queue owns, which arrives with #168. It is named in the PR
body as owed rather than quietly dropped.
"""
import json
import threading
import time
import types

import pytest

from sunglasses.proxy import bounds, pump


def test_the_eighth_outstanding_request_is_still_admitted():
    """Eight is the cap, not seven. A bound that refuses AT the limit is a
    different promise from one that refuses past it, and this one counts items
    already held -- so the eighth is the last one in, not the first one out."""
    session = pump.Session()
    for request_id in range(bounds.OUTSTANDING):
        assert session.admit_request(request_id, method="ping", origin="client"), (
            f"request {request_id} was refused below the cap of {bounds.OUTSTANDING}")


def test_the_ninth_outstanding_request_is_refused():
    """T801. The ninth is the one the table forbids, and refusing the NEW item
    is T6.R7: a held message is never dropped to make room, because dropping
    one withdraws an answer somebody is already waiting for."""
    session = pump.Session()
    for request_id in range(bounds.OUTSTANDING):
        assert session.admit_request(request_id, method="ping", origin="client")
    assert not session.admit_request(bounds.OUTSTANDING, method="ping",
                                     origin="client")


def test_the_refusal_is_recorded_as_overloaded():
    """A refusal nobody can see in the receipts is a session that silently
    stops accepting work. The emit carries the reason the table names."""
    session = pump.Session()
    seen = []
    original = session._core._emit
    session._core._emit = lambda event, *a, **k: (
        seen.append((event, k.get("reason"))), original(event, *a, **k))[1]
    for request_id in range(bounds.OUTSTANDING):
        assert session.admit_request(request_id, method="ping", origin="client")
    assert not session.admit_request(99, method="ping", origin="client")
    assert ("ADMISSION_REFUSED", "OVERLOADED") in seen, seen


def test_an_upstream_request_is_not_counted_against_the_client_cap():
    """The row counts CLIENT correlations. Counting upstream's own requests
    against the same cap would let a chatty server close the client's window,
    which is the opposite of what a bound on admission is for."""
    session = pump.Session()
    for request_id in range(bounds.OUTSTANDING):
        assert session.admit_request(request_id, method="ping", origin="client")
    # The client cap is full; upstream's namespace is its own.
    assert session.admit_request(1, method="ping", origin="upstream")


def test_an_upstream_correlation_does_not_consume_the_client_cap():
    """The distinguishing control, and the reason it exists is worth writing
    down: the row above cannot separate "count client correlations" from "count
    everything", because an upstream admission skips the cap entirely either
    way. Only a session holding BOTH can tell them apart.

    One upstream request outstanding, then the client's full eight. If the
    count is of everything, the eighth client is refused by a correlation the
    client did not make -- a server that keeps one request open would
    permanently cost the client a slot.
    """
    session = pump.Session()
    assert session.admit_request(1, method="ping", origin="upstream")
    for request_id in range(bounds.OUTSTANDING):
        assert session.admit_request(request_id, method="ping", origin="client"), (
            f"client request {request_id} was refused with an upstream "
            f"correlation outstanding; the cap is counting the wrong things")
    assert not session.admit_request(bounds.OUTSTANDING, method="ping",
                                     origin="client")


# ── round 2, R-179-R2 ───────────────────────────────────────────────────────
#
# ASTRA's independent probe found four ways past the round-1 bound and one
# reading of the row I had narrowed without saying so. These rows are the
# corrections, and each one is written from the control that caught it rather
# than from the code that failed.

def _fill(session, n=bounds.OUTSTANDING, origin="client"):
    return all(session.admit_request(i, method="ping", origin=origin)
               for i in range(n))


def test_an_item_being_answered_is_still_outstanding():
    """AR05. The window between `_pending` and retirement is not a rare race.

    A response leaves `_pending` and sits in `_settling` while the handoff to
    the client completes. Round 1 counted `_pending` alone, so during EVERY
    response the session would admit a ninth correlation -- the client is still
    waiting for that answer and its id is still ours. The probe held the
    handoff open with the existing barrier and got nine.
    """
    session = pump.Session()
    assert _fill(session)
    entered, release = threading.Event(), threading.Event()
    original = session._settle_outside_lock

    def held(identity):
        entered.set()
        release.wait(5)
        return original(identity)

    session._settle_outside_lock = held
    worker = threading.Thread(
        target=lambda: session.deliver_response(origin="upstream", request_id=0))
    worker.start()
    try:
        assert entered.wait(3), "the handoff barrier never opened"
        assert not session.admit_request(bounds.OUTSTANDING, method="ping",
                                         origin="client"), (
            "a ninth correlation was admitted while the eighth was mid-handoff")
        assert len(session._pending) + len(session._settling) == bounds.OUTSTANDING
    finally:
        release.set()
        worker.join(5)


def test_two_admissions_at_the_boundary_cannot_both_win(monkeypatch):
    """AR06. The check and the insert are one step, or the cap is advisory.

    Round 1 read the occupancy outside the lock: two admissions both read seven
    and both inserted, giving nine pending against a cap of eight -- no fault
    injection, just two threads.

    TWO NOTES ON THE CONTROL, because the first two attempts were both worse
    than the bug.

    ASTRA's probe held both threads INSIDE `check_admission` on a barrier. That
    is only reachable while the check sits outside the lock, so against the fix
    the barrier can never fill and the probe dies with BrokenBarrierError --
    the instrument breaking, not the property failing.

    Racing four bare threads is the opposite failure: it PASSES against the
    broken head, because the unlocked window is a few bytecodes wide and the
    GIL closes it nearly every time. A control that cannot fail against the
    defect it names is not evidence.

    So the window is widened rather than synchronised: `check_admission` sleeps
    after it answers. Outside a lock that sleep lets the second thread read the
    same occupancy and both insert; inside one it makes the second thread wait,
    which is the whole difference being asserted.
    """
    slow = bounds.check_admission

    def measured(**kwargs):
        answer = slow(**kwargs)
        time.sleep(0.02)
        return answer

    monkeypatch.setattr(bounds, "check_admission", measured)
    session = pump.Session()
    assert _fill(session, bounds.OUTSTANDING - 1)
    answers = []
    start = threading.Barrier(4)

    def race(request_id):
        start.wait(5)
        answers.append(session.admit_request(request_id, method="ping",
                                             origin="client"))

    threads = [threading.Thread(target=race, args=(i,)) for i in range(100, 104)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
    assert len(answers) == 4, answers
    assert sum(answers) == 1, (
        f"{sum(answers)} admissions won ONE free slot; the check and the insert "
        f"are not one step")
    assert len(session._pending) == bounds.OUTSTANDING, len(session._pending)


def test_a_refused_item_gets_a_terminal_settlement_not_just_a_false():
    """AR07. A boolean is not a receipt.

    Round 1 emitted ADMISSION_REFUSED and returned False, and nothing said the
    item had ENDED. T6.R7 names the refusal S3 `OVERLOADED`; a terminal
    settlement carrying exactly that is what makes the refusal gradeable
    against the row, and what stops the caller inventing a reason.
    """
    session = pump.Session()
    assert _fill(session)
    assert not session.admit_request(99, method="ping", origin="client")
    terminal = [event for event in session._core.events
                if event["kind"] == "SETTLED" and event.get("rule") == "S3"
                and event.get("reason_code") == "OVERLOADED"]
    assert len(terminal) == 1, [e["kind"] for e in session._core.events]


def test_the_refusal_names_its_own_cause_to_the_caller():
    """AR07, the half that reaches the user.

    `route.py` answered every non-closing refusal with UNINSPECTED_METHOD, so a
    bound breach told a well-behaved client that its method could not be
    inspected. The session now says why, and the only reason the route layer
    still carries a default is that T2.R16's refusal decides before the bound
    and has no Cause of its own.
    """
    session = pump.Session()
    assert _fill(session)
    assert not session.admit_request(99, method="ping", origin="client")
    refusal = session.refusal_for(99, origin="client")
    assert refusal is not None and refusal.reason == "OVERLOADED"
    assert refusal.rule == "S3"
    assert session.refusal_for(0, origin="client") is None, (
        "an admitted id is carrying a refusal")


def test_a_duplicate_id_at_capacity_is_malformed_not_overloaded():
    """DP01. Malformed before resource.

    At capacity, round 1 refused a duplicate id as OVERLOADED: the client broke
    T6.R6 and was told the server was busy, the session stayed open, and both
    ends went on disagreeing about what that id names. Protocol validation
    decides first; only a well-formed request can be too many.
    """
    session = pump.Session()
    assert _fill(session)
    assert not session.admit_request(0, method="ping", origin="client")
    assert session._closed is not None, "a duplicate id at capacity did not close"
    assert session._closed[0] == "MALFORMED_CLIENT", session._closed


def test_the_upstream_origin_has_a_bound_of_its_own():
    """AR04, by refinement.

    The row names outstanding correlations with no origin qualifier. Read
    literally -- one shared count of eight -- an upstream request permanently
    costs the client a slot, which is what the two rows above this block
    refuse. Read as round 1 read it, upstream was UNBOUNDED, which is worse: a
    server could open correlations for ever. Each origin is bounded separately
    at the same figure, so neither can spend the other's window and neither is
    free. The contract copy carries this as the T8.R6 origin scope note (v5.2).
    """
    session = pump.Session()
    assert _fill(session, bounds.OUTSTANDING, origin="upstream")
    assert not session.admit_request(bounds.OUTSTANDING, method="ping",
                                     origin="upstream"), (
        "the ninth UPSTREAM correlation was admitted; that origin is unbounded")
    # And the client's window is untouched by all eight of them.
    assert _fill(session, bounds.OUTSTANDING, origin="client")


def test_the_client_is_told_overloaded_and_not_uninspected_method():
    """AR07's client half, and the one change here a user can see.

    `route.py` answered EVERY non-closing refusal with UNINSPECTED_METHOD. So a
    client that did nothing wrong, and whose method is perfectly inspectable,
    was told its method could not be inspected -- a receipt that cannot be
    graded against the row that actually fired, and advice nobody can act on.
    The row it breached says S3 `OVERLOADED`, and that is what has to arrive.

    This drives the real `Route` rather than the pump alone, because the
    defect was in the translation between them: the pump knew the reason all
    along and the route layer was not asking.
    """
    from sunglasses.proxy.route import Route

    written = []
    session = pump.Session(strict=False)
    route = Route(session=session, log=None, upstream_write=lambda raw: None,
                  client_write=written.append,
                  scan=lambda params, **kw: pytest.fail(
                      "a refused request reached the scanner"),
                  catalog=frozenset(),
                  approvals=types.SimpleNamespace(may_call=lambda *a: None))
    route._record = lambda event, **kw: True
    assert _fill(session)

    frame = {"jsonrpc": "2.0", "id": 99, "method": "tools/call",
             "params": {"name": "echo", "arguments": {"text": "ordinary"}}}
    route.client_frame((json.dumps(frame) + "\n").encode())

    assert written, "the client was told nothing at all"
    answered = [json.loads(raw) for raw in written]
    reasons = [body.get("error", {}).get("data", {}).get("reason_code")
               or body.get("result", {}).get("reason_code")
               for body in answered]
    assert "OVERLOADED" in reasons, answered
    assert "UNINSPECTED_METHOD" not in reasons, (
        "the bound breach still reaches the client as an inspection refusal")


# ── round 3, R-179-R3 ───────────────────────────────────────────────────────
#
# ASTRA drove round 2 through the real Route twice and found two defects in the
# round-2 repair itself. Both come from the same mistake in different clothes:
# state that belongs to ONE ATTEMPT was stored against the identity, where a
# later attempt could read it or a paused earlier one could overwrite it.

def test_a_second_refusal_reports_its_own_reason_not_the_previous_one():
    """XE02. The refusal a caller is holding is the one it gets told about.

    Round 2 kept the cause keyed by identity and cleared it only on success. So
    an id refused OVERLOADED, then refused again by T2.R16 for an unknown
    method, still answered the client OVERLOADED -- the route asked why, and
    was told why the PREVIOUS attempt failed. On main that same sequence is
    green, because main has nothing to remember; the regression arrived WITH
    the repair, which is the kind this file exists to catch.
    """
    session = pump.Session()
    assert _fill(session)
    assert not session.admit_request(99, method="ping", origin="client")
    assert session.refusal_for(99, origin="client").reason == "OVERLOADED"
    # Same id, a different refusal, decided before the bound is ever consulted.
    assert not session.admit_request(99, method="extension/unknown",
                                     origin="client")
    refusal = session.refusal_for(99, origin="client")
    assert refusal.reason == "UNINSPECTED_METHOD", (
        f"the second attempt was reported as {refusal.reason}, which is why "
        f"the first one failed")


def test_a_paused_refusal_cannot_rename_a_later_admission():
    """XR03. A generation, once handed out, is never taken back.

    Round 2 reserved the refused attempt's generation in a SECOND critical
    section inside `_refuse_overloaded`, after the section that took the
    decision had been released. Pause a refusal between the two, let an
    ordinary admission of the same id complete in the gap, and the refusal's
    bump renamed the live item's key: the core still owed an entry the pump no
    longer had, and the reader raised.

    ASTRA drove it through two real `Route.client_frame` calls. Driven here at
    the pump, which is the layer that owns the generation.
    """
    session = pump.Session()
    assert _fill(session)
    entered, release = threading.Event(), threading.Event()
    original = session._refuse_overloaded

    def held(*args):
        entered.set()
        release.wait(5)
        return original(*args)

    session._refuse_overloaded = held
    failures = []

    def refuse():
        try:
            session.admit_request(99, method="ping", origin="client")
        except Exception as error:            # noqa: BLE001 - the point of the row
            failures.append(type(error).__name__)

    worker = threading.Thread(target=refuse)
    worker.start()
    try:
        assert entered.wait(3), "the refusal never reached its report"
        # One slot frees, and the SAME id is admitted for real while the
        # earlier attempt is still parked mid-report.
        session.deliver_response(origin="upstream", request_id=0)
        assert session.admit_request(99, method="ping", origin="client")
        live = session._core_key(pump.key("client", 99))
    finally:
        release.set()
        worker.join(5)
    assert not failures, failures

    # THE DISCRIMINATOR, and the first draft of this row missed it. Counting
    # pending against owed passes on the broken head, because the damage is not
    # a missing entry -- it is that the identity's generation moved UNDER a live
    # item. On 184188f the live admission holds key (..., 1) while the counter
    # reads 2, so every later lookup for this id computes a key the core does
    # not own, and the orphan only surfaces when the reader tries to settle it.
    # A row that waits for the symptom would have passed on the defect.
    recomputed = session._core_key(pump.key("client", 99))
    assert recomputed == live, (
        f"the live item was admitted as {live} and is now looked up as "
        f"{recomputed}; the earlier attempt moved its generation")
    assert recomputed in session._core.owed(), "the live item is not owed"
    assert len(session._pending) == len(session._core.owed())

    # And it can still be answered, which is what ownership is FOR.
    session.deliver_response(origin="upstream", request_id=99)
    assert session._core.settled_as(live) is not None, (
        "the live item could not be settled after the earlier attempt resumed")


def test_the_refusal_receipt_carries_no_prose():
    """My own audit finding, ruled in as R-179-R3(3).

    Round 2 emitted `detail="8 correlations already outstanding"` into the
    event stream. `Cause.as_receipt` excludes `detail` BY NAME and says why --
    the frame receipt leaked peer material through exactly that field twice --
    and an emit that adds it back defeats the allowlist from the other side.
    WHICH BOUND broke is a fixed vocabulary and is what a reader needs.
    """
    session = pump.Session()
    assert _fill(session)
    assert not session.admit_request(99, method="ping", origin="client")
    refused = [e for e in session.events if e["kind"] == "ADMISSION_REFUSED"]
    assert len(refused) == 1, [e["kind"] for e in session.events]
    assert "detail" not in refused[0], refused[0]
    assert refused[0]["bound"] in ("outstanding", "queued"), refused[0]
    assert refused[0]["origin"] == "client", refused[0]
