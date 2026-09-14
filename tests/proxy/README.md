# `tests/proxy/`

`test_independent.py` is ASTRA's file, vendored UNCHANGED from the PR #164
review of f43781b. Its sha256 is the one in that review's `SHA256SUMS`.

It is here as an acceptance set, not as a starting point. Editing it to make it
pass would destroy the only property that makes it worth having, which is that
it was written by somebody who did not write the code and did not know which
assertions the code would happen to satisfy. Seven mutations survived my own 47
tests and none survived this file.

If a check here is wrong, it is resolved with ASTRA and a new file is vendored.
It is not edited in place.

`ROOT` in that file points at `/private/tmp/PR164_REVIEW_f43781b_2026-09-13`,
which is the review's own fixture tree. The durable copy lives in
`Desktop/SUNGLASSES_ASTRA_REVIEW_2026-09-04/PR164_REVIEW_f43781b_2026-09-13/fixtures`.

## Known failing checks, and why they are not silently resolved

As of the round 2 file, four checks fail, and neither is fixed by editing
anything in this directory.

**Q12 and Q13** depend on a pump that does not exist yet. A response cannot be
validated against the request it answers while `Session._owed` stores timestamps
rather than expected methods, and no component yet reads a stream. ASTRA's own
verdict classes both as integration absences under NOT IN THIS HEAD. They are
the next slice.

**Q14 contradicts C03.** Both make the identical call on an identical session:

    s = Session(); s.admit(41)
    s.settle(999, Cause('CLEAN', 'S1'))

C03 requires that this returns None, settles nothing, and leaves 41 owed with
the session open. Q14 requires that the same call tears the session down and
settles 41 as MALFORMED_UPSTREAM. Implementing Q14 turns C03 red for all three
of its parameters and C11 red for all three of its, six control checks, which
was measured and not reasoned about.

Both readings are defensible. T7.R1 names an unsolicited response as an S5
trigger, which argues for Q14. C03 and C11 are labelled passing controls and
exercise the API the way a caller uses it, which argues that an unowned id
handed to a method is not by itself a wire event. The difference is most likely
the origin parameter the API still does not have, which is what ASTRA asked for
in round 1 and which the pump will need anyway.

The behaviour kept here is C03 and C11, because a control that a repair turns
red is a louder signal than a regression check that stays red.

### Ruling, T9, 2026-09-13

Stated to ASTRA in the round 3 prompt so he can overrule it with a row id.

> C03 stands at the API. `settle(999, CLEAN)` on a session that owes 41 is a
> caller handing an unowned id to a method. The S5 trigger in T7.R1 and T6.R6 is
> a WIRE event: an unsolicited response FRAME arriving from upstream. Those are
> different things and the API must not conflate them. The API refuses without
> state change; the pump, on receiving an unsolicited upstream response frame,
> records the S5 cause and tears down, which is Q14's behaviour at the frame
> boundary.

Implemented. `Session.settle` takes an `origin`, defaulting to `api`. An unowned
id from `api` is refused and changes nothing; an unowned id from `upstream`
records MALFORMED_UPSTREAM and closes the session, answering whatever was owed
rather than stranding it. `Session.admit` also records the method a request was
issued with, so a response can be checked against the request it claims to
answer; `_owed` held a bare timestamp, which is why Q13 could not be satisfied
at all.

Q14 therefore still fails as written, because it calls the API with no origin.
That is expected under this ruling rather than an outstanding defect. The
behaviour it asks for is covered by
`test_an_unowned_id_from_the_wire_closes_the_session` in
`tests/test_proxy_session.py`, and the pump will exercise it at the boundary.


## A second contradiction, across rounds this time

Round 1's `test_independent.py::test_R2_stop_failure_must_not_lose_settlement_delivery`
and round 3's `test_round3.py::test_V04_failed_supervisor_cannot_be_bypassed_by_default_retry`
cannot both pass.

Both drive the same sequence: a teardown whose supervisor raises, then a second
teardown with no callback argument.

R2 requires that second call to return a non-empty batch, so the settlements are
not lost. V04 requires that the child actually be stopped before any batch is
handed back, and accepts the retry raising instead. With a supervisor that
always raises, the child is alive, so a non-empty batch satisfies R2 and fails
V04, and a raise satisfies V04 and fails R2.

Measured both ways rather than argued:

    with the retained supervisor    R2 fails, V04 passes
    without it                      R2 passes, V04 fails

The retention is kept, so V04 passes and R2 fails. V04 is the later round and it
refines exactly what R2 was reaching for: R2 says do not lose the batch, V04
adds do not claim closure while the process is still running. Losing the batch
was the round 1 defect; claiming an uncompleted close is the worse one, because
a receipt that says the upstream closed is evidence and a missing batch is a
retry.

Recorded for ASTRA the same way the Q14 and C03 contradiction was, and resolved
the same way if he disagrees: by a ruling and a new versioned file, not by
editing either of these.
