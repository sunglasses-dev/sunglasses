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
    inspected. The session now says why.

    R-179-R4: it says it TO THE CALLER, into a place that caller owns. Round 2
    and round 3 both put the cause in a table keyed by the id, and an id is
    shared by every attempt that ever uses it.
    """
    session = pump.Session()
    assert _fill(session)
    mine = []
    assert not session.admit_request(99, method="ping", origin="client",
                                     on_refusal=mine.append)
    assert len(mine) == 1 and mine[0].cause.reason == "OVERLOADED"
    assert mine[0].cause.rule == "S3"
    # An admission that SUCCEEDS tells its caller nothing, because there is
    # nothing to tell -- not "nothing left over from someone else".
    theirs = []
    session.deliver_response(origin="upstream", request_id=0)
    assert session.admit_request(77, method="ping", origin="client",
                                 on_refusal=theirs.append)
    assert theirs == []


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
    first = []
    assert not session.admit_request(99, method="ping", origin="client",
                                     on_refusal=first.append)
    assert first[0].cause.reason == "OVERLOADED"
    # Same id, a different refusal, decided before the bound is ever consulted.
    second = []
    assert not session.admit_request(99, method="extension/unknown",
                                     origin="client", on_refusal=second.append)
    assert second[0].cause.reason == "UNINSPECTED_METHOD", (
        f"the second attempt was reported as {second[0].cause.reason}, which is why "
        f"the first one failed")
    # R-179-R4, the half round 3 could not express: the FIRST attempt's answer
    # is untouched by the second. With a shared table the earlier caller read
    # the later caller's reason (XE03_OVERLAP), and it could only be caught by
    # holding both answers at once -- which is what these two lists do.
    assert first[0].cause.reason == "OVERLOADED", (
        f"the first attempt's cause became {first[0].cause.reason} when a second "
        f"attempt on the same id was refused")


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


def test_an_earlier_refusal_cannot_retire_a_later_live_request(tmp_path):
    """XR03_OWNER. The row round 3 passed for the wrong reason.

    Two attempts on id 99: the first is refused at the cap and parked
    mid-report, a slot frees, the second is ADMITTED and forwarded upstream.
    When the first resumes it must touch nothing of the second's.

    Round 3 reserved the generation correctly and still failed this, because
    the ROUTE side was keyed by the id alone: the refused attempt's
    `_withhold` called `settle_from(CLIENT, 99, ...)` and retired the live
    request as UNINSPECTED_METHOD. The live item ended neither owed nor
    answerable -- pending 0, owed 0.

    ASTRA's older XR03_ROUTE row read that as a PASS, because its predicate is
    "no orphan AND a terminal exists", and settling the live item early
    satisfies both. That row is RETIRED rather than repaired (T9, R-179-R4):
    its predicate can only be met by the defect this one names. Measured, same
    row, same file: round 3 `orphaned_live=False, pending 7 = owed 7`; round 4
    `pending 8 = owed 8` with the item still answerable.
    """
    from sunglasses.proxy import receipts
    from sunglasses.proxy.route import Route

    written = []
    session = pump.Session()
    route = Route(session=session, log=receipts.Log(tmp_path, run_id="r4",
                                                    header={}),
                  upstream_write=lambda raw: None,
                  client_write=written.append, scan=None, catalog=frozenset())
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
            route.client_frame(json.dumps(
                {"jsonrpc": "2.0", "id": 99, "method": "ping"}).encode() + b"\n")
        except Exception as error:            # noqa: BLE001
            failures.append(type(error).__name__)

    worker = threading.Thread(target=refuse)
    worker.start()
    try:
        assert entered.wait(3), "the refusal never reached its report"
        session.deliver_response(origin="upstream", request_id=0)
        route.client_frame(json.dumps(
            {"jsonrpc": "2.0", "id": 99, "method": "ping"}).encode() + b"\n")
        live = session._core_key(pump.key("client", 99))
    finally:
        release.set()
        worker.join(5)

    assert not failures, failures
    assert live in session._core.owed(), (
        "the earlier refusal retired the later live request")
    assert pump.key("client", 99) in session._pending
    assert session._core.settled_as(live) is None, (
        "the live request was given a terminal before its answer arrived")
    # And it can still be answered exactly once, which is the whole point of
    # keeping it: the client asked, and an answer is owed.
    assert session.deliver_response(origin="upstream", request_id=99) is not None


# ── round 5, R-179-R5 · the attempt token, end to end ───────────────────────

def test_every_refusal_reserves_a_generation(tmp_path):
    """R4_UNKNOWN_TOKEN. Round 4 reserved for the bound refusal and not for the
    unknown-method one, so that refusal reached the route with no attempt
    identity at all -- a structural hole, not a wrong answer."""
    session = pump.Session()
    identity = pump.key("client", 99)
    seen = []
    for _ in range(2):
        before = session._generation.get(identity, 0)
        assert not session.admit_request(99, method="extension/unknown",
                                         origin="client",
                                         on_refusal=seen.append)
        assert session._generation.get(identity, 0) > before, (
            "the unknown-method refusal reserved no generation")
    assert [a.token for a in seen] == [identity + (1,), identity + (2,)], seen
    assert {a.cause.reason for a in seen} == {"UNINSPECTED_METHOD"}


def test_an_older_withheld_attempt_cannot_settle_a_newer_generations_debt(tmp_path):
    """R-179-R5, the reachable form of R4_WITHHOLD_OWNER.

    ASTRA reached this property through a step ruling (3) now refuses -- a
    response to a request that was withheld and never forwarded -- so his row
    is retired as "setup step refused by (3)" and this is the reachable
    variant: an older attempt withheld with its writer paused before the
    trailing settlement, a NEW attempt admitted and forwarded on the same id,
    then the older writer resumes.

    Two things were wrong when this was first measured, and both were the same
    mistake at different levels. `settle_from` recomputed the CURRENT
    generation, so the older settlement popped the newer entry. And the
    attempt was parked on `self`, so the second `client_frame` overwrote it and
    the older call, resuming, claimed the NEWER attempt's item -- the newer
    request lost its debt and the older kept it. The token is a LOCAL that
    travels as a parameter now, which is what "end to end" means.
    """
    from sunglasses.proxy import receipts
    from sunglasses.proxy.route import Route

    entered, release = threading.Event(), threading.Event()
    written, forwarded, failures = [], [], []

    def client_write(raw):
        if threading.current_thread().name == "older":
            entered.set()
            release.wait(5)
        written.append(raw)

    session = pump.Session()
    route = Route(session=session,
                  log=receipts.Log(tmp_path, run_id="r5", header={}),
                  upstream_write=forwarded.append, client_write=client_write,
                  catalog=frozenset(),
                  approvals=types.SimpleNamespace(
                      may_call=lambda *a: "APPROVAL_REQUIRED",
                      invalidate=lambda: None))

    def older():
        try:
            route.client_frame(json.dumps(
                {"jsonrpc": "2.0", "id": 99, "method": "tools/call",
                 "params": {"name": "review"}}).encode() + b"\n")
        except Exception as error:            # noqa: BLE001
            failures.append(type(error).__name__)

    worker = threading.Thread(target=older, name="older")
    worker.start()
    try:
        assert entered.wait(3), "the older attempt never reached its write"
        older_token = session._core_key(pump.key("client", 99))
        route.client_frame(json.dumps(
            {"jsonrpc": "2.0", "id": 99, "method": "ping"}).encode() + b"\n")
        live = session._core_key(pump.key("client", 99))
    finally:
        release.set()
        worker.join(5)

    assert not failures, failures
    assert older_token != live, "the newer attempt reserved no generation"
    assert live in session._core.owed(), "the newer attempt lost its debt"
    assert pump.key("client", 99) in session._pending
    assert session._core.settled_as(live) is None, (
        "the older attempt settled the newer generation's item")
    assert session._core.settled_as(older_token) is not None, (
        "the older attempt's own debt was left owed for the session")


def test_a_response_to_a_request_that_was_never_forwarded_is_refused(tmp_path):
    """R-179-R5/(3). A withheld request never reaches upstream, so a response
    carrying its id is unsolicited by construction.

    THE WINDOW IS THE ROW. Round 4 left the item in `_pending` until the
    withhold's TRAILING settlement, which runs after the client frame is
    written -- so a response arriving in between was ACCEPTED for a request
    upstream had never seen, and ASTRA built R4_WITHHOLD_OWNER on that step.
    Outside the window the old head refuses it too, so a row that does not
    pause the writer passes on the defect. This one pauses it.
    """
    from sunglasses.proxy import receipts
    from sunglasses.proxy.route import Route

    entered, release = threading.Event(), threading.Event()
    written, accepted = [], []

    def client_write(raw):
        entered.set()
        release.wait(5)
        written.append(raw)

    session = pump.Session()
    route = Route(session=session,
                  log=receipts.Log(tmp_path, run_id="r5b", header={}),
                  upstream_write=lambda raw: None, client_write=client_write,
                  catalog=frozenset(),
                  approvals=types.SimpleNamespace(
                      may_call=lambda *a: "APPROVAL_REQUIRED",
                      invalidate=lambda: None))
    worker = threading.Thread(target=lambda: route.client_frame(json.dumps(
        {"jsonrpc": "2.0", "id": 99, "method": "tools/call",
         "params": {"name": "review"}}).encode() + b"\n"))
    worker.start()
    try:
        assert entered.wait(3), "the withheld answer never reached the writer"
        accepted.append(session.deliver_response(
            origin="upstream", request_id=99,
            frame={"jsonrpc": "2.0", "id": 99, "result": {"content": []}}))
    finally:
        release.set()
        worker.join(5)

    assert accepted == [None], (
        "a response was accepted for a request that was withheld and never "
        "forwarded, in the window between the answer and its settlement")


def test_settle_from_settles_the_generation_it_was_given_or_refuses():
    """R-179-R5, the last two instances of the class.

    `settle_from` recomputed `_core_key(identity)` after popping, which is the
    current generation by definition. A caller holding an attempt passes its
    token and settles exactly that; a stale token is a typed refusal, because
    the item that caller is talking about is gone and settling something else
    in its place is the whole defect.
    """
    session = pump.Session()
    identity = pump.key("client", 7)
    assert session.admit_request(7, method="ping", origin="client")
    stale = session._core_key(identity)
    # The first attempt is answered and a SECOND is admitted on the same id.
    assert session.settle_from("client", 7, "UNINSPECTED_METHOD", "S1",
                               token=stale) is not None
    assert session.admit_request(7, method="ping", origin="client")
    live = session._core_key(identity)
    assert live != stale

    refused = session.settle_from("client", 7, "UNINSPECTED_METHOD", "S1",
                                  token=stale)
    assert refused is None, "a stale token settled something"
    assert live in session._core.owed(), (
        "the stale settlement took the live generation's debt")
    assert identity in session._pending


def test_a_cancellation_settles_the_generation_it_observed():
    """The same class in the cancellation path, driven through the window.

    `cancel` settled `_core_key(identity)` at the END of the call -- current by
    definition -- so a generation admitted between the pop and the settle is
    the one that gets cancelled. `_remember_tombstone` runs in exactly that gap,
    which makes it the seam to drive: admit a NEW attempt there and the old
    head cancels the newcomer.

    The first draft of this row asserted only that the observed token was
    settled, with no interleaving, and it passed on the defect -- the fourth
    control this week that was green on the thing it was written to catch.
    """
    session = pump.Session()
    identity = pump.key("client", 7)
    assert session.admit_request(7, method="ping", origin="client")
    observed = session._core_key(identity)

    original = session._remember_tombstone

    def admit_a_newcomer(ident):
        session._remember_tombstone = original       # once
        assert session.admit_request(7, method="ping", origin="client")
        return original(ident)

    session._remember_tombstone = admit_a_newcomer
    session.cancel(7, origin="client")

    live = session._core_key(identity)
    assert live != observed, "the newcomer reserved no generation"
    assert session._core.settled_as(observed) is not None, (
        "the cancellation did not settle the item it observed")
    assert session._core.settled_as(live) is None, (
        "the cancellation settled a generation admitted after it")
    assert live in session._core.owed()


# ── round 6 · what a refusal is allowed to touch ────────────────────────────

def _route_for(session, tmp_path, *, client_write=None, upstream_write=None):
    """The real Route over a real log, with approvals that always hold.

    Every round-6 row drives ordinary frames through this rather than calling
    the pump directly: four of ASTRA's seven are reachable only through the
    route, and a row that pokes the pump would measure a composition no client
    can actually produce.
    """
    from sunglasses.proxy import receipts
    from sunglasses.proxy.route import Route

    return Route(session=session,
                 log=receipts.Log(tmp_path, run_id="r6", header={}),
                 upstream_write=upstream_write or (lambda raw: None),
                 client_write=client_write or (lambda raw: None),
                 catalog=frozenset(),
                 approvals=types.SimpleNamespace(
                     may_call=lambda *a: "APPROVAL_REQUIRED",
                     invalidate=lambda: None))


def _request(request_id, method):
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method,
                       "params": {"name": "review"}}).encode() + b"\n"


def test_a_refusal_never_renames_a_live_request(tmp_path):
    """R5_UNKNOWN_LIVE. The refusal path reserved a generation FIRST.

    An unknown method was refused before any of the three protocol tests ran,
    and refusing reserves -- which bumps the very counter that identifies the
    live correlation already standing under that id. So an unknown method sent
    on a pending id renamed the pending request's core key: the core went on
    owing the old one, `_core_key` returned the new one, and the real answer
    when it arrived settled a generation nobody owned while the original debt
    stayed owed with no pending entry to find it by. Pending 0, owed 1, no
    exception anywhere.

    Ownership is decided before anything is reserved now, so the duplicate is
    what it has always been -- a protocol fault -- and the refusal can only
    ever reserve on an id that owns nothing.
    """
    session = pump.Session()
    forwarded = []
    route = _route_for(session, tmp_path, upstream_write=forwarded.append)
    route.client_frame(_request(99, "ping"))
    live = session._core_key(pump.key("client", 99))
    assert live in session._core.owed(), "the ping was never really forwarded"

    route.client_frame(_request(99, "extension/unknown"))

    assert session._core_key(pump.key("client", 99)) == live, (
        "the refusal moved the generation that names the live request")
    assert session.closed_with() is not None, (
        "reusing a pending id is a protocol fault whatever method it carries")
    assert not session._core.owed(), (
        f"the live debt was orphaned: {session._core.owed()}")


def test_a_paused_owner_keeps_the_claim_on_its_own_item(tmp_path):
    """R5_UNKNOWN_WITHHOLD. The same generation move, from the other side.

    An admitted request is paused at its withhold, an unknown method arrives on
    the same id, and the older caller resumes to find its claim REFUSED --
    because the generation it owns is no longer the current one. Its core debt
    was settled and its pending entry was left behind: pending with no owed
    owner, the exact mirror of the row above. The route ignored the failed
    claim and carried on.
    """
    session = pump.Session()
    entered, release, failures = threading.Event(), threading.Event(), []
    original = pump.Session.claim_for_local_answer

    def paused(self, token):
        if threading.current_thread().name == "older":
            entered.set()
            assert release.wait(5)
        return original(self, token)

    session.claim_for_local_answer = types.MethodType(paused, session)
    route = _route_for(session, tmp_path)

    def older():
        try:
            route.client_frame(_request(99, "tools/call"))
        except Exception as error:            # noqa: BLE001
            failures.append(type(error).__name__)

    worker = threading.Thread(target=older, name="older")
    worker.start()
    try:
        assert entered.wait(3), "the older attempt never reached its claim"
        route.client_frame(_request(99, "extension/unknown"))
    finally:
        release.set()
        worker.join(5)

    assert not failures, failures
    assert not session._pending, f"a pending entry was stranded: {session._pending}"
    assert not session._core.owed(), f"a debt was stranded: {session._core.owed()}"


def test_a_locally_claimed_answer_still_counts_against_the_bound(tmp_path):
    """R5_LOCAL_CAP, and a REGRESSION of the bound this PR exists to add.

    Claiming an attempt for a local answer takes it out of `_pending` before
    the frame is written, which is what makes a later upstream response
    unsolicited (round 5's own fix). It also took it out of the count: eight
    refused attempts parked at their writers counted ZERO, and a ninth request
    was admitted with nine debts owed. Round 4 refused that ninth in the same
    window, so this is the bound going backwards, not a pre-existing gap --
    and T8.R6 names in-flight held messages explicitly.
    """
    entered, release, failures = threading.Condition(), threading.Event(), []
    arrived = [0]

    def client_write(raw):
        with entered:
            arrived[0] += 1
            entered.notify_all()
        assert release.wait(5)

    session = pump.Session()
    route = _route_for(session, tmp_path, client_write=client_write)

    def offer(request_id):
        try:
            route.client_frame(_request(request_id, "tools/call"))
        except Exception as error:            # noqa: BLE001
            failures.append(type(error).__name__)

    workers = [threading.Thread(target=offer, args=(i,))
               for i in range(bounds.OUTSTANDING)]
    for worker in workers:
        worker.start()
    try:
        with entered:
            ready = entered.wait_for(lambda: arrived[0] == bounds.OUTSTANDING, 3)
        assert ready, f"only {arrived[0]} attempts reached their writer"
        admitted = session.admit_request(99, method="ping", origin="client")
        owed_at_cap = len(session._core.owed())
    finally:
        release.set()
        for worker in workers:
            worker.join(5)

    assert not failures, failures
    assert owed_at_cap == bounds.OUTSTANDING, owed_at_cap
    assert not admitted, (
        "a ninth correlation was admitted while eight answers were mid-write")


def test_a_claimed_answer_does_not_make_upstream_solicited(tmp_path):
    """The other half of the row above, and the reason `_claimed` is its own
    table rather than a second home in `_settling`.

    Counting the item again must not undo what claiming it was FOR: the
    request was never forwarded, so a response carrying its id is unsolicited
    by construction and stays that way while the local answer is being written.
    """
    session = pump.Session()
    route = _route_for(session, tmp_path)
    attempts = []
    session.admit_request(5, method="tools/call", origin="client",
                          on_attempt=attempts.append)
    assert session.claim_for_local_answer(attempts[0].token)
    with session._settlement:
        counted = session._outstanding_locked("client")
    assert counted == 1, "the claim stopped counting"
    assert not session.expects(5, origin="client"), (
        "a claimed item still reads as one upstream may answer")


def test_a_teardown_racing_the_settlement_never_raises_at_a_client(tmp_path):
    """R5_WITHHOLD_CLOSE, in its reachable form.

    Round 5 added an already-settled guard as `settled_as` and then `settle`:
    two acquisitions of the core's lock with a legitimate `_close` able to land
    between them, so the teardown settled the token and the settle that
    followed raised `Settled` out of `Route.client_frame` -- an exception
    reaching a client where a receipt belongs. ADJACENT LINES ARE NOT
    ATOMICITY, the same sentence as #168's round 5, one module over.

    ASTRA's row pauses `settled_as`, which the fix DELETES from this path, so
    his barrier can no longer fill: superseded, not satisfied, and measured as
    zero calls rather than asserted. This drives the same race on the seam that
    replaced it.
    """
    session = pump.Session()
    entered, release, failures = threading.Event(), threading.Event(), []

    # BOTH SEAMS ARE ARMED AND THE FIRST ONE TO FIRE WINS, because the row
    # has to pause wherever the implementation ACTUALLY decides, not wherever
    # this file guesses it does.
    #
    # On the old head the window is AFTER `settled_as` has answered "not
    # settled" and before `settle` acts on that answer, so that seam pauses on
    # the way out. On the fixed head there is no between -- decision and action
    # are one call under the core's lock -- so the closest reachable drive is a
    # teardown completing immediately BEFORE the call, and that seam pauses on
    # the way in.
    #
    # Two earlier shapes of this row were measured and thrown away. Wrapping
    # `settle_or_report` alone was an AttributeError on `d72dc43`: a red that
    # says only "this method is new", which is the API-shape red ASTRA counted
    # three of last round. Then CHOOSING the seam by what the core offers made
    # the P04 mutant -- which leaves `settle_or_report` defined and stops
    # calling it -- fail on "the settlement was never reached", a kill scored
    # from a barrier that never filled rather than from behaviour.
    fired = []

    def arm(name, before):
        original = getattr(session._core, name, None)
        if original is None:
            return

        def paused(*args, **kwargs):
            mine = (threading.current_thread().name == "older"
                    and not fired)
            if mine and before:
                fired.append(name)
                entered.set()
                assert release.wait(5)
            value = original(*args, **kwargs)
            if mine and not before:
                fired.append(name)
                entered.set()
                assert release.wait(5)
            return value

        setattr(session._core, name, paused)

    arm("settle_or_report", before=True)
    arm("settled_as", before=False)
    route = _route_for(session, tmp_path)

    def older():
        try:
            route.client_frame(_request(99, "tools/call"))
        except Exception as error:            # noqa: BLE001
            failures.append(type(error).__name__)

    worker = threading.Thread(target=older, name="older")
    worker.start()
    try:
        assert entered.wait(3), "the settlement was never reached"
        session._close("MALFORMED_CLIENT", "a legitimate teardown")
    finally:
        release.set()
        worker.join(5)

    assert not failures, f"an exception reached the client: {failures}"
    assert not session._core.owed(), session._core.owed()


def test_the_settled_guard_is_one_call_and_not_two():
    """The shape, pinned, because the timing row above can only catch it when
    the timing repeats. `settle_attempt` must not ask the core a question and
    then act on the answer in a second call."""
    import ast
    import inspect
    import textwrap

    tree = ast.parse(textwrap.dedent(
        inspect.getsource(pump.Session.settle_attempt)))
    called = {ast.unparse(node.func) for node in ast.walk(tree)
              if isinstance(node, ast.Call)}
    assert "self._core.settled_as" not in called, (
        "the guard is a check followed by a separate action again")
    assert "self._core.settle_or_report" in called, called


def test_a_stale_token_cancels_nothing(tmp_path):
    """R5_STALE_CANCEL. The optional token is new API and was never validated.

    `cancel` popped the pending entry and tombstoned the id BEFORE looking at
    the token it was handed, so a cancellation carrying the token of an attempt
    that had already been answered retired the LIVE request admitted on that id
    afterwards -- and tombstoned the id for the rest of the session. The newer
    request kept its debt and lost its correlation.
    """
    session = pump.Session()
    session.admit_request(7, method="ping", origin="client")
    stale = session._core_key(pump.key("client", 7))
    session.deliver_response(origin="upstream", request_id=7)
    session.admit_request(7, method="ping", origin="client")
    live = session._core_key(pump.key("client", 7))
    assert stale != live

    session.cancel(7, origin="client", token=stale)

    assert live in session._core.owed(), "the live request lost its debt"
    assert pump.key("client", 7) in session._pending, (
        "the live request lost its pending correlation")
    assert pump.key("client", 7) not in session._tombstones, (
        "a stale cancellation tombstoned an id it does not own")


def test_an_attempt_cannot_be_edited_after_it_is_issued():
    """R5_IMMUTABLE_ATTEMPT. The docstring claimed it since round 5.

    Only the TUPLE the property returns was immutable. The carrier was not, so
    `attempt.generation += 1` changed the token every later reader would be
    handed -- an id-only key with extra steps, which is the defect this lane
    has spent five rounds on.
    """
    session = pump.Session()
    issued = []
    session.admit_request(99, method="extension/unknown", origin="client",
                          on_refusal=issued.append)
    attempt = issued[0]
    before = attempt.token
    with pytest.raises(AttributeError):
        attempt.generation += 1
    assert attempt.token == before


def test_a_withhold_with_no_attempt_refuses_instead_of_settling_twice(tmp_path):
    """R5_NOATTEMPT_REFUSAL. The comment promised a refusal; the code wrote
    two successful settlements.

    The no-attempt branch recorded SETTLED and then fell through to a second
    unconditional SETTLED below it: two terminal receipts for an item that was
    never settled at all, on the one path whose whole point is that nobody owns
    the thing being answered.
    """
    session = pump.Session()
    route = _route_for(session, tmp_path)
    events = []
    route._record = lambda event, **fields: events.append(event) or True

    route._withhold(99, "UNINSPECTED_METHOD", "S1")

    assert events.count("SETTLED") == 0, events
    assert events.count("SETTLEMENT_REFUSED") == 1, events


def test_a_close_while_an_answer_is_claimed_still_pays_that_debt(tmp_path):
    """The third table has to be drained, or counting it creates the hole.

    `_close` retains what is owed by walking `_pending` and `_settling`. An
    attempt claimed for a local answer is in neither, so adding the table
    without adding it here would be RC13's "in neither table" window with a new
    name: a client blocked on a request the teardown never records a debt for,
    and never answers. Measured rather than assumed, because the fix for the
    bound and the hole in the close are one line apart.
    """
    session = pump.Session()
    attempts = []
    session.admit_request(5, method="tools/call", origin="client",
                          on_attempt=attempts.append)
    assert session.claim_for_local_answer(attempts[0].token)

    session._close("MALFORMED_UPSTREAM", "a teardown mid-answer")

    assert not session._core.owed(), (
        f"the claimed attempt's debt was never recorded: {session._core.owed()}")
    owed_ids = [identity for identity, _, _ in session._owed_refusals]
    assert pump.key("client", 5) in owed_ids, (
        "the close retained no refusal for the item being answered")
