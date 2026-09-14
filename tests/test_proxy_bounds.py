"""T8's bounds table, specified from the rows before the module exists.

Fourteen rows, and the ones that bite are not the numbers. A bound is three
decisions and only the first is the value: what the limit IS, whether it is
inclusive, and what a breach is CALLED. Getting the number right and the
inclusivity wrong is an off-by-one that hands an attacker exactly one free byte
at every boundary, and getting the name wrong makes a real breach ungradeable
against the fixtures.

So every row here is checked at the boundary, not in the middle: at the limit,
one under, and one over. A test that asserts 5,000 bytes is under a 262,144 cap
has proved nothing about the cap.

Deadlines take an injected clock. A test that sleeps is slow, flaky on a shared
runner, and tests the scheduler as much as the rule.
"""
import pytest

bounds = pytest.importorskip("sunglasses.proxy.bounds",
                             reason="bounds is the slice being specified here")


# ── the frozen values, asserted rather than trusted ───────────────────────

def test_the_frozen_values_are_the_ones_the_rows_name():
    """Written out so a silent edit to a constant fails here rather than
    somewhere subtle three rows away."""
    assert bounds.WIRE_FRAME_BYTES == 4_194_304          # R1
    assert bounds.CONTENT_BYTES == 262_144               # R2
    assert bounds.FRAME_ASSEMBLY_MS == 2_000             # R3
    assert bounds.INSPECTION_MS == 2_000                 # R4
    assert bounds.KILL_GRACE_MS == 250                   # R4
    assert bounds.UPSTREAM_RESPONSE_MS == 60_000         # R5
    assert bounds.OUTSTANDING == 8                       # R6
    assert bounds.QUEUED_BYTES == 16 * 1024 * 1024       # R6
    assert bounds.WORKER_STDOUT_BYTES == 1024 * 1024     # R7
    assert bounds.STDERR_PER_MESSAGE == 256 * 1024       # R8
    assert bounds.WRITE_STALL_MS == 5_000                # R9
    assert bounds.WATCHDOG_SLACK_MS == 3_000             # R10
    assert bounds.MAX_DEPTH == 64 and bounds.MAX_NODES == 100_000   # R11
    assert bounds.SNAPSHOT_PAGES == 64                   # R13
    assert bounds.SNAPSHOT_TOOLS == 512                  # R13
    assert bounds.SNAPSHOT_BYTES == 4 * 1024 * 1024      # R13
    assert bounds.SNAPSHOT_DEADLINE_MS == 10_000         # R13


# ── R2: inclusive at the budget, and the boundary is where it is tested ───

@pytest.mark.parametrize("size,breached", [
    (bounds.CONTENT_BYTES - 1, False),
    (bounds.CONTENT_BYTES, False),        # "262,144 inclusive"
    (bounds.CONTENT_BYTES + 1, True),
])
def test_the_content_budget_is_inclusive_at_the_limit(size, breached):
    """R2 says inclusive, and G2-23/content_exact and G2-07/bytes_262144 are
    both exactly at it. An exclusive reading fails two shipped fixtures."""
    outcome = bounds.check_content(size)
    assert bool(outcome) is breached
    if breached:
        assert outcome.reason == "OVER_BUDGET" and outcome.budget == "content"
        assert outcome.rule == "S3"
        assert outcome.inspection_complete is False


@pytest.mark.parametrize("size,breached", [
    (bounds.WIRE_FRAME_BYTES, False),
    (bounds.WIRE_FRAME_BYTES + 1, True),
])
def test_the_frame_bound_is_inclusive_and_names_the_frame_budget(size, breached):
    outcome = bounds.check_frame(size)
    assert bool(outcome) is breached
    if breached:
        assert (outcome.reason, outcome.budget) == ("OVER_BUDGET", "frame")


# ── R6: two limits, one reason, and the NEW item is the one refused ───────

@pytest.mark.parametrize("outstanding,queued,breached", [
    (bounds.OUTSTANDING - 1, 0, False),
    (bounds.OUTSTANDING, 0, True),
    (0, bounds.QUEUED_BYTES, False),
    (0, bounds.QUEUED_BYTES + 1, True),
])
def test_admission_is_refused_when_either_limit_is_reached(outstanding, queued,
                                                          breached):
    """R6 bounds outstanding correlations AND queued bytes. Checking one and not
    the other leaves the whole limit reachable through the other."""
    outcome = bounds.check_admission(outstanding=outstanding, queued=queued)
    assert bool(outcome) is breached
    if breached:
        assert outcome.reason == "OVERLOADED" and outcome.rule == "S3"


def test_overload_refuses_the_new_item_and_never_drops_a_held_one():
    """T6.R7 and R6's last clause. Dropping a held message to make room
    withdraws an answer somebody is already waiting for."""
    assert bounds.overload_victim() == "new"


# ── deadlines, on an injected clock ───────────────────────────────────────

@pytest.mark.parametrize("elapsed,expired", [
    (bounds.INSPECTION_MS - 1, False),
    (bounds.INSPECTION_MS, False),
    (bounds.INSPECTION_MS + 1, True),
])
def test_the_inspection_clock_expires_after_the_limit_not_at_it(elapsed, expired):
    outcome = bounds.check_deadline("inspection", elapsed_ms=elapsed)
    assert bool(outcome) is expired
    if expired:
        assert outcome.reason == "SCAN_DEADLINE" and outcome.rule == "S3"
        assert outcome.budget is None, (
            "SCAN_DEADLINE is not a budget breach and must not name one")


@pytest.mark.parametrize("name,limit", [
    ("frame_assembly", bounds.FRAME_ASSEMBLY_MS),
    ("inspection", bounds.INSPECTION_MS),
    ("upstream_response", bounds.UPSTREAM_RESPONSE_MS),
    ("write_stall", bounds.WRITE_STALL_MS),
])
def test_every_named_deadline_uses_its_own_limit(name, limit):
    """One shared constant would make four different rows the same number, and
    they are not: 2,000 ms to assemble a frame and 60,000 ms for an upstream to
    answer are different promises."""
    assert not bounds.check_deadline(name, elapsed_ms=limit)
    assert bounds.check_deadline(name, elapsed_ms=limit + 1)


def test_an_unknown_deadline_name_is_refused_rather_than_defaulted():
    """A typo that silently picks a default gives a bound nobody chose."""
    with pytest.raises(KeyError):
        bounds.check_deadline("made_up", elapsed_ms=1)


def test_the_watchdog_fires_past_any_deadline_not_at_it():
    """R10: 3,000 ms PAST any deadline. The watchdog exists to catch a deadline
    that did not fire, so it must sit strictly outside the longest one it
    guards."""
    assert bounds.watchdog_deadline_ms("inspection") == (
        bounds.INSPECTION_MS + bounds.WATCHDOG_SLACK_MS)
    assert bounds.watchdog_deadline_ms("upstream_response") > \
        bounds.UPSTREAM_RESPONSE_MS


# ── R13: snapshot totals, four limits and a cursor rule ───────────────────

@pytest.mark.parametrize("kwargs,breached", [
    (dict(pages=bounds.SNAPSHOT_PAGES, tools=1, decoded=1, elapsed_ms=1), False),
    (dict(pages=bounds.SNAPSHOT_PAGES + 1, tools=1, decoded=1, elapsed_ms=1), True),
    (dict(pages=1, tools=bounds.SNAPSHOT_TOOLS + 1, decoded=1, elapsed_ms=1), True),
    (dict(pages=1, tools=1, decoded=bounds.SNAPSHOT_BYTES + 1, elapsed_ms=1), True),
    (dict(pages=1, tools=1, decoded=1,
          elapsed_ms=bounds.SNAPSHOT_DEADLINE_MS + 1), True),
])
def test_each_snapshot_total_is_bounded_separately(kwargs, breached):
    outcome = bounds.check_snapshot(**kwargs)
    assert bool(outcome) is breached
    if breached:
        assert outcome.reason == "APPROVAL_REQUIRED" and outcome.rule == "S4"


def test_a_repeated_cursor_is_a_fault_not_a_stopping_condition():
    """R13: cursor repeats = fault. A server that keeps returning the same
    cursor would otherwise page for ever, and stopping quietly would activate a
    PREFIX of the descriptor set, which the row forbids in its last words."""
    outcome = bounds.check_snapshot(pages=2, tools=1, decoded=1, elapsed_ms=1,
                                    cursors=["a", "a"])
    assert outcome and outcome.reason == "APPROVAL_REQUIRED"
    assert "cursor" in (outcome.detail or "")


def test_a_breached_snapshot_never_activates_a_prefix():
    """The row's last clause, as its own assertion because it is the
    consequence that matters rather than the counting."""
    assert bounds.may_activate_partial_snapshot() is False


# ── R14: exit status ──────────────────────────────────────────────────────

@pytest.mark.parametrize("fatal,upstream_code,pending,expected", [
    (True, 0, False, 1),       # a fatal fault is nonzero ALWAYS
    (True, 0, True, 1),
    (False, 0, False, 0),      # clean exit, nothing owed, propagated
    (False, 3, False, 3),      # propagated, not normalised
    (False, 0, True, 1),       # exit with pending calls is S5
])
def test_exit_status_follows_the_row(fatal, upstream_code, pending, expected):
    assert bounds.exit_status(fatal=fatal, upstream_code=upstream_code,
                              pending=pending) == expected


def test_a_clean_upstream_code_is_propagated_rather_than_flattened():
    """"propagated" is the row's word. Flattening every clean exit to zero
    throws away the server's own answer about how it ended."""
    assert bounds.exit_status(fatal=False, upstream_code=7, pending=False) == 7
