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


## A third contradiction, inside one file this time

Round 4's `test_W03_G2_22_actual_child_exit_pending` and
`test_F15_exit_pending_yields_client_withheld_error` describe the same
situation and require opposite results.

Both drive an EMPTY upstream with exactly one pending client request, which is
the G2-22 shape: `exit_with_pending.upstream.jsonl` is a zero-byte file. W03
requires `read_upstream` to yield nothing. F15 requires it to yield exactly one
frame, the client's SUNGLASSES_WITHHELD error with code -32070.

Measured both ways rather than argued:

    yielding the refusal      W03 fails, F15 passes
    recording it only         W03 passes, F15 fails

The refusal is kept, so F15 passes and W03 fails. T6.R1 gives a client request
at most one response and the client is WAITING: recording the fault and saying
nothing leaves it waiting for ever on a session that has already decided it is
over. A test that expects silence there is asking for a hang.

W03's other three assertions all hold either way, and they are the substantive
ones: the session closes MALFORMED_UPSTREAM, the item settles MALFORMED_UPSTREAM,
and the exit code is nonzero. Only its assertion about the yielded list
conflicts.

Recorded for ASTRA the way the Q14/C03 and R2/V04 contradictions were, and to be
resolved the same way, by a ruling and a new versioned file rather than by
editing either check.


## F21, and why it stays red with the mechanism built

T9's ruling: an upstream exit is a PROCESS fact and must never be inferred from
silence. An inactivity deadline cannot tell a dead leader with a lingering
grandchild from a healthy server thinking hard, and would eventually fire on
both, so it is not an option in this code however convenient it looks.

The mechanism the contract asks for is built: `Session(upstream=..., pgid=...)`
and `attach_upstream(handle, pgid)`. The pump waits on the HANDLE rather than
the pipe, records S5 on an exit with pending calls per T7.R1, and then stops the
group per T8.R12, which closes the descendant's copy of the write end and is
what actually releases the reader. Strict mode refuses to read at all without a
handle, because an upstream nobody supervises is exactly this hang and that
should be a startup error rather than a quieter mode that fails later and less
clearly.

`test_an_upstream_exit_with_pending_calls_closes_even_though_the_pipe_stays_open`
in `tests/test_proxy_pump.py` drives the F21 shape end to end with real
processes and passes: leader spawns a grandchild, leader exits 0, grandchild
holds stdout, and the reader is released with `MALFORMED_UPSTREAM`.

F21 itself constructs `pump.Session()` with no arguments and hands it only
`leader.stdout`, so no handle is ever attached and there is no process for the
pump to wait on. As written it can only be satisfied by the inactivity heuristic
the ruling forbids. It stays red, ASTRA decides in the combined review, and the
behaviour it is reaching for is demonstrated by the test named above.

## G2-15 reverse wire, the fourth contradiction, measured both ways

`scripts/test_reverse_wire.py` asserts two things in this order, 0.3 s after the
peer signals ready:

    assert not out                            # line 21
    assert (tmp_path/'response.bin').exists()  # line 22

They cannot both hold once the row is actually implemented, and the reason is
`reverse_peer.py` rather than either assertion. The peer's last two statements
are `response=sys.stdin.buffer.readline()` and a write of that line, so the
moment the proxy answers the reverse request the peer RETURNS and its stdout
closes. The client's own request, admitted from the requests fixture and sharing
id 1501 on purpose, is still pending at that EOF, and T7.R1 makes an upstream
exit with pending calls an S5 fault whose one owed answer T6.R1 requires on the
wire. So the refusal arrives inside the same 0.3 s.

Measured both ways on this head:

  WITHOUT the upstream response (the graded candidate): the peer blocks on
  readline for ever, no EOF arrives, `out` stays empty and line 21 passes;
  `response.bin` is never written and line 22 fails. That is the shape ASTRA
  graded NON-CONFORMANT.

  WITH the upstream response (this head): `response.bin` contains
  `reason_code: UNINSPECTED_METHOD` and line 22 passes; the peer exits, T7.R1
  fires, and `out` holds exactly one frame, so line 21 fails.

The single frame in `out` is
`{"jsonrpc":"2.0","id":1501,"error":{"code":-32070,"message":"SUNGLASSES_WITHHELD","data":{"reason_code":"MALFORMED_UPSTREAM","rule":"S5"}}}`.
It is a settlement of the CLIENT's own pending request, not a relay of anything
the server sent. The substantive property line 21 exists to protect holds
exactly: the server's `sampling/createMessage` frame, its params and its text
never reach the client, and the id in the refusal is the client's own typed id
answering the client's own request.

So line 21 is a "nothing was relayed to C" assertion written for a peer that
never exits, and it reads as false against a peer that exits the instant it is
answered. T9 rules. The row itself is implemented: `_respond_upstream` writes
one JSON-RPC error in upstream's id namespace back up the pipe, and nothing is
ever yielded toward the client from the reverse branch.

## The empty-output assertion, now in sixteen more places

C07 and W01 use the SAME fixture, `G2-10/invalid_json`, and require opposite
things. C07 asserts the client pipe receives a refusal whose `reason_code`
equals `closed_with()[0]`. W01 asserts `not got`. Implementing the bounded
repair route therefore turns sixteen round-4 controls red, and every one of
them is red on that clause alone. Counted from a run rather than by eye, since
the first version of this paragraph said fourteen and then listed sixteen:

    W01 x2, W02 x5, W05 x1, F06 x1, F08 x4, F11 x1, F14 x1, W20 x1   = 16
    plus test_reverse_wire.py line 21                                = 17

    tests/proxy total reds = 19, of which W03 and F21 are the two already
    ruled, leaving 17 on the empty-output clause.

Measured on this head, all five W02 variants:

    invalid_utf8          closed=(MALFORMED_UPSTREAM,S5) as expected, 1 frame, id 2103, reason MALFORMED_UPSTREAM, settled S5
    duplicate_keys        closed=(MALFORMED_UPSTREAM,S5) as expected, 1 frame, id 2102, reason MALFORMED_UPSTREAM, settled S5
    ambiguous_result      closed=(MALFORMED_UPSTREAM,S5) as expected, 1 frame, id 2104, reason MALFORMED_UPSTREAM, settled S5
    malformed_clean_tail  closed=(MALFORMED_UPSTREAM,S5) as expected, 1 frame, id 2101, reason MALFORMED_UPSTREAM, settled S5
    deep_json             closed=(OVER_BUDGET,S3)        as expected, 1 frame, id 2105, reason OVER_BUDGET,        settled S3

Every substantive half still holds. The close reason and rule match the row, the
item settles under the right rule, and what is yielded is exactly ONE frame: a
SUNGLASSES_WITHHELD error carrying the CLIENT's own typed id and the same
reason_code the session closed with. Nothing the server sent is relayed, which
is the property the empty-output assertion was written to protect.

This is the shape ASTRA already withdrew once. The verdict says "W03's old
empty-output assertion is withdrawn while its three substantive assertions
stand", and W01, W02, W05, F06, F08, F11, F14, W20 and reverse-wire line 21 all
carry the same clause, written when a fault yielded nothing because the refusal
had not been built yet. T6.R1 gives a client request exactly one response and
C07 now requires it on these exact paths, so silence here is the hang F15 ruled
against.

Not repaired by editing a control. Measured, written down, and T9 rules.


## R-W03-2, the ruling, and what was done to each of the seventeen

T9 ruled at 04:48 on 2026-09-14. The empty-output clause is WITHDRAWN on all
seventeen controls that carried it, the same shape ASTRA withdrew for W03 at
03:24: the clause was written when a fault yielded nothing because the refusal
did not exist yet, and T6.R1 with C07 now require exactly one typed refusal on
those paths, so silence there is the hang F15 ruled against.

Nothing of ASTRA's was deleted or rewritten to pass. Each control was SPLIT in
place, three ways:

  1. the original test keeps its substantive assertions UNCHANGED, plus a
     direct assertion of the property the withdrawn clause was protecting
     (nothing the server sent reaches the client, named by its own bytes);
  2. the empty-output assertion becomes its own test marked
     `xfail(strict=True, reason=R_W03_2)`, so it is a TRIPWIRE. If the refusal
     ever disappears and the pipe goes silent again, that xfail XPASSes and the
     suite goes red. The clause still watches the thing it was written for;
     it has stopped asserting the opposite of the contract;
  3. a positive control per fixture asserts what C07 requires instead: exactly
     ONE frame, SUNGLASSES_WITHHELD, the client's own typed id, and
     `reason_code == closed_with()[0]`.

The seventeen, counted from a run rather than by eye:

    W01 x2   invalid_json, invalid_result_shape
    W02 x5   invalid_utf8, duplicate_keys, ambiguous_result,
             malformed_clean_tail, deep_json
    W05 x1   G2-20 unsolicited
    F06 x1   LF in the frame budget
    F08 x4   tools/call {}, tools/call 7, tools/list {}, tools/list []
    F11 x1   unfrozen initialize version
    F14 x1   fault stops the real child
    W20 x1   tools/list shape
    G2-15    reverse wire, line 21
                                                            total = 17

Two more xfails exist beside them and are NOT part of R-W03-2:

    W03   its empty-output assertion was withdrawn by ASTRA himself at 03:24;
          the three substantive assertions stand and are live. C01 in
          test_round5.py is his corrected control and it passes.
    F21   ruling D. As written it attaches no handle, so the exit can only be
          observed by an inactivity heuristic, which T9 forbids in security
          code. C02 in test_round5.py is the corrected control and it passes
          both ways.

Result on this head: `tests/proxy` is 214 passed, 3 skipped, 19 xfailed, zero
failed. The whole proxy suite is 315 passed, 19 xfailed, zero failed. The
round-2 prompt asks ASTRA to version these as CONTROLS_CORRECTION v6.

---

## R-RC18-1, the ruling (T9, 2026-09-14)

`test_round6_edges.py` is edited in ONE line and nothing else in it.

    file    tests/proxy/test_round6_edges.py
    before  dd80bc1ce6e6f64545fc9ff6137445a1312b68dbdfc7dc306c3ff1c33205bc10
    after   88d1e6a2628bc783cc168eece6b18614818cde1bfb8da169d54e824d62c364f4

    -  target=start+max(i for i,line in enumerate(src) if line.strip()=='yield raw')
    +  target=start+max(i for i,line in enumerate(src) if line.strip().startswith('yield self._handoff(identity'))

**Behaviour asserted unchanged; selector follows the ruled line.**

The control asserts a BEHAVIOUR at a boundary: a close completing while the
reader is parked at the delivery line, before that line runs, must win, so no
original crosses and every id is still answered exactly once. The ruled
implementation satisfies that at the same instant -- measured with a barrier
placed there, the record is still owed, the close wins, two frames go out, both
ids appear once and zero originals cross.

The selector is only the instrument's way of FINDING that instant by text, and
the text changed because the ruling put the decision on that line. RC18 is
repaired by moving the decision INTO the yield expression, since only an
expression is evaluated when the line runs; a statement before it runs too
early, and the close then finds the record already discharged and stands down
while the resumed reader delivers anyway.

Left unchanged the control fails on a TIMEOUT rather than on behaviour: with no
line matching `yield raw` in the response path, `max()` falls back to the
notification path's line, which never executes in this scenario, so `entered`
never sets. That is a check that cannot fail for the reason it exists.

One consequence of the repair is recorded here because it touches every
consumer: a refused handoff yields `b""` rather than `None`. A consumer writes
what the reader yields, and on a byte stream `b""` IS nothing -- it writes zero
bytes and needs no special case. `None` would make every consumer, including a
reviewer's, carry a check it never needed, and ASTRA's own control writes the
yielded value unconditionally: with `None` it raised TypeError in place of a
refusal.

Our own suite pins the property independently of this selector
(`test_the_handoff_decision_is_made_by_the_yield_and_not_before_it`), because a
behaviour only a reviewer's instrument can observe is one we cannot
regression-test. The round-7 prompt carries this as CONTROLS_CORRECTION v7
alongside R-RC03-1 and R-T903-1, and asks ASTRA to re-issue the selector in a
text-independent form if he prefers -- an ast walk for the yield whose value
calls `_handoff`.
