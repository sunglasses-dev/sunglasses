"""T7.R2 and T4.R4 Rule A: settle once, with the cause that came first.

The hard part of a teardown is not killing processes. It is this sentence from
T7.R2: "settle each KNOWN pending client request ONCE with the FIRST recorded
cause and rule". Three claims hide in it and each fails quietly on its own.
"""
import threading

import pytest

from sunglasses.proxy import framing
from sunglasses.proxy.session import Cause, Session, Settled


def _protocol():
    return Cause(framing.MALFORMED_UPSTREAM, framing.S5, detail="duplicate key")


def _deadline():
    return Cause("SCAN_DEADLINE", framing.S3)


def _cancelled():
    return Cause("REQUEST_CANCELLED", "S6")


# ── ONCE ────────────────────────────────────────────────────────────────────

def test_an_item_is_settled_once_and_a_second_attempt_raises():
    """Two answers for one id means the client keeps whichever arrived last."""
    session = Session()
    session.admit(7)
    session.settle(7, _deadline())
    with pytest.raises(Settled) as again:
        session.settle(7, _protocol())
    assert "already settled" in str(again.value)
    assert session.settled_as(7).reason == "SCAN_DEADLINE"


def test_a_second_teardown_settles_nothing_new_and_redelivers_the_batch():
    """Settling happens once. DELIVERING the answers may happen again.

    This asserted that a repeat teardown returns `{}`. ASTRA's review showed
    what that costs: the supervisor ran before the batch was returned, so a
    supervisor that raised took the only copy of the answers with it, and the
    retry reported nothing to deliver while every item was already settled.
    Losing the batch is the failure; re-handing it to a caller is not.
    """
    session = Session()
    session.admit(1)
    first = session.teardown(_protocol())
    assert set(first) == {1}

    again = session.teardown(_deadline())
    assert again == first, "the batch was not redelivered"
    settled = [e for e in session.events if e["kind"] == "SETTLED"]
    assert len(settled) == 1, "the second teardown settled something again"
    assert session.settled_as(1).reason == framing.MALFORMED_UPSTREAM


def test_two_threads_racing_to_settle_produce_one_answer():
    """The check and the settle have to be one atomic step.

    Separate locks for pending and settled, or a check outside the lock, lets
    both threads pass the check and both write.
    """
    session = Session()
    session.admit("r")
    winners, start = [], threading.Barrier(8)

    def attempt(n):
        start.wait()
        try:
            session.settle("r", Cause(f"CAUSE{n}", framing.S3))
            winners.append(n)
        except Settled:
            pass

    threads = [threading.Thread(target=attempt, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(winners) == 1, f"{len(winners)} threads each settled the same item"


# ── KNOWN ───────────────────────────────────────────────────────────────────

def test_what_is_owed_is_what_was_forwarded_and_not_yet_answered():
    """Not what is being scanned. By the time a teardown runs the scans may have
    finished and left; what remains owed is everything still unanswered."""
    session = Session()
    for request_id in (1, 2, 3):
        session.admit(request_id)
    session.settle(2, Cause("CLEAN", "S1"))
    assert sorted(session.owed()) == [1, 3]
    assert sorted(session.teardown(_protocol())) == [1, 3]


def test_nothing_is_admitted_once_teardown_has_begun():
    """A request admitted after the decision to stop is one nothing will answer."""
    session = Session()
    assert session.admit(1) is True
    session.teardown(_protocol())
    assert session.admitting() is False
    assert session.admit(2) is False
    assert 2 not in session.owed()


# ── THE FIRST CAUSE ─────────────────────────────────────────────────────────

def test_a_later_cancellation_does_not_rewrite_an_earlier_fault():
    """T4.R4 Rule A. A fault does not become a different fault because
    something else arrived afterwards."""
    session = Session()
    session.admit(11)
    session.record(11, _deadline())
    session.record(11, _cancelled())
    assert session.terminal_cause(11).reason == "SCAN_DEADLINE"
    assert session.teardown(_protocol())[11].reason == "SCAN_DEADLINE"


def test_the_later_cause_is_still_recorded_even_though_it_lost():
    """The receipt has to be able to show that a later cause arrived and did not
    win. Dropping it makes the record agree with the rule by having no evidence
    against it."""
    session = Session()
    session.admit(12)
    session.record(12, _deadline())
    session.record(12, _cancelled())
    assert [c.reason for c in session.causes(12)] == [
        "SCAN_DEADLINE", "REQUEST_CANCELLED"]


def test_an_item_with_no_cause_of_its_own_takes_the_teardown_cause():
    session = Session()
    session.admit(13)
    assert session.teardown(_protocol())[13].reason == framing.MALFORMED_UPSTREAM


def test_an_item_that_already_failed_is_not_relabelled_by_the_session_ending():
    """The two halves of the same rule, in one test, because getting one right
    and the other wrong is the likely outcome."""
    session = Session()
    session.admit("own"), session.admit("none")
    session.record("own", _deadline())
    answers = session.teardown(_protocol())
    assert answers["own"].reason == "SCAN_DEADLINE"
    assert answers["none"].reason == framing.MALFORMED_UPSTREAM


def test_first_recorded_wins_even_when_a_later_cause_outranks_it():
    """The distinction that makes `terminal_cause` order-based and not
    precedence-based.

    A protocol fault outranks a deadline in T4.R4's numbered order, which
    settles causes known at the SAME instant. It must NOT let a protocol fault
    recorded LATER rewrite a deadline recorded earlier, which is Rule A. Sorting
    `terminal_cause` by precedence would read correctly and be wrong.
    """
    session = Session()
    session.admit(14)
    session.record(14, _deadline())
    session.record(14, _protocol())
    assert session.terminal_cause(14).reason == "SCAN_DEADLINE"

    # And precedence still applies where precedence is the question.
    winner = Session.precedence_winner([_deadline(), _protocol()])
    assert winner.reason == framing.MALFORMED_UPSTREAM


@pytest.mark.parametrize("causes,expected", [
    ([_deadline(), _cancelled()], framing.MALFORMED_UPSTREAM),
    ([_cancelled(), _deadline()], "REQUEST_CANCELLED"),
])
def test_precedence_orders_causes_known_at_one_settlement_instant(causes, expected):
    if expected == framing.MALFORMED_UPSTREAM:
        causes = causes + [_protocol()]
    assert Session.precedence_winner(causes).reason == expected


# ── the session's own outcome ───────────────────────────────────────────────

def test_a_session_that_tore_down_exits_nonzero():
    """A zero exit is read by everything upstream of us as "it worked"."""
    session = Session()
    assert session.exit_code() == 0
    session.teardown(_protocol())
    assert session.exit_code() == 1


def test_the_processes_are_stopped_once_and_after_everything_is_settled():
    """Killing first would leave items owed with nothing left to answer them.

    Observed through the session's own events rather than by patching `settle`,
    because the teardown settles through an internal path that holds the lock
    and a patched public method simply would not see it. A test that watches a
    method the code under test no longer calls reports whatever it likes.
    """
    session = Session()
    session.admit(1)
    stops = []
    session.teardown(_protocol(), stop_processes=lambda: stops.append(1))
    session.teardown(_deadline(), stop_processes=lambda: stops.append(2))

    assert stops == [1], "the supervisor ran again on the repeat teardown"
    kinds = [e["kind"] for e in session.events]
    assert kinds.index("SETTLED") < kinds.index("UPSTREAM_CLOSED"), kinds


def test_a_failed_supervisor_is_remembered_and_retried_not_skipped():
    """Round 3 V04, which supersedes what this test used to assert.

    It required that a retry with no callback hand the batch back, so the
    settlements were not lost with the supervisor. That is half the rule. The
    other half is that a retry which cannot establish the processes actually
    stopped must not claim a close: the default argument is not a statement that
    nothing needs stopping, it is a caller who did not say.

    So the failed supervisor is retained and re-run. Losing the batch was the
    round 1 defect; announcing a close while the child is still alive is the
    worse one, because a receipt saying the upstream closed is evidence and a
    missing batch is only a retry.
    """
    session = Session()
    session.admit(1)
    attempts = []

    def explode():
        attempts.append(1)
        raise ProcessLookupError("the leader had already exited")

    with pytest.raises(ProcessLookupError):
        session.teardown(_protocol(), stop_processes=explode)
    with pytest.raises(ProcessLookupError):
        session.teardown(_deadline())          # no callback, retained one runs
    assert attempts == [1, 1], "the retry skipped supervision entirely"
    assert not [e for e in session.events if e["kind"] == "UPSTREAM_CLOSED"], (
        "a close was announced while the supervisor had never completed")

    # And once something does stop them, the batch is delivered and the item
    # keeps the cause it was settled with.
    answers = session.teardown(_deadline(), stop_processes=lambda: None)
    assert set(answers) == {1}
    assert session.settled_as(1).reason == framing.MALFORMED_UPSTREAM


def test_the_receipt_shows_the_teardown_and_what_it_settled():
    session = Session()
    session.admit(1)
    session.record(1, _deadline())
    session.teardown(_protocol())
    kinds = [e["kind"] for e in session.events]
    # SESSION_TORN_DOWN rather than UPSTREAM_CLOSED, because this teardown was
    # given no supervisor. Claiming the upstream closed when nothing supervised
    # the processes puts a false sentence in the evidence while a child may
    # still be running, which is ASTRA's F14.
    assert kinds == ["CAUSE_RECORDED", "TEARDOWN", "SETTLED",
                     "SESSION_TORN_DOWN"]
    assert session.events[-1]["settled"] == 1
    assert session.events[-1]["supervised"] is False
    stamps = [e["mono"] for e in session.events]
    assert stamps == sorted(stamps)


# ── the origin distinction, T9's ruling of 2026-09-13 ──────────────────────
# ASTRA's C03 and his Q14 make the identical call and require opposite outcomes.
# They are both right about different things, and the API could not tell them
# apart because it had no way to say where a settlement came from.
#
# The ruling: an unsolicited response is a WIRE event, a response FRAME arriving
# from upstream for an id nobody issued. A caller handing this object an id it
# does not own is not that. So the origin is stated, and these tests are what
# make the parameter more than documentation.

def test_an_unowned_id_from_a_caller_changes_nothing():
    """C03's requirement, which is the default because most callers are us."""
    session = Session()
    session.admit(41)
    assert session.settle(999, Cause("CLEAN", "S1")) is None
    assert not session.is_settled(999)
    assert session.owed() == [41], "the pending item was disturbed"
    assert not session.torn_down


def test_an_unowned_id_from_the_wire_closes_the_session():
    """Q14's requirement, at the boundary where it belongs.

    T7.R1 names an unsolicited response an S5 trigger. It is a fact about the
    peer, so the session cannot continue, and the item that WAS owed is answered
    rather than stranded.
    """
    session = Session()
    session.admit(41)
    assert session.settle(999, Cause("CLEAN", "S1"),
                          origin=session_origin_upstream()) is None
    assert session.torn_down
    assert session.settled_as(41).reason == framing.MALFORMED_UPSTREAM
    assert not session.is_settled(999), "the unissued id was never ours to answer"


def session_origin_upstream():
    from sunglasses.proxy.session import ORIGIN_UPSTREAM
    return ORIGIN_UPSTREAM


def test_the_default_origin_is_the_caller_not_the_wire():
    """A default that closed sessions would make every API slip a teardown."""
    from sunglasses.proxy.session import ORIGIN_API
    import inspect

    default = inspect.signature(Session.settle).parameters["origin"].default
    assert default == ORIGIN_API


def test_a_pending_id_remembers_what_it_is_waiting_for():
    """`_owed` held a bare timestamp, which is why a response could not be
    checked against the request it claims to answer. The pump reads this."""
    session = Session()
    session.admit(41, method="tools/call")
    session.admit(42)
    assert session.expected_method(41) == "tools/call"
    assert session.expected_method(42) is None
    assert session.expected_method(999) is None, "not pending, not an answer"
    session.settle(41, Cause("CLEAN", "S1"))
    assert session.expected_method(41) is None, "settled is no longer pending"
