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
red is a louder signal than a regression check that stays red. This is recorded
for resolution with ASTRA rather than decided by whoever edits next.
