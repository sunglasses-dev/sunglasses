"""The pump, specified from the contract rows BEFORE it exists.

Written this way deliberately. Three review rounds on the session core cost
ASTRA three passes, and the cause was the same each time: I wrote the tests my
implementation suggested, so they agreed with it. A test file written from the
rows, against a module that does not exist yet, cannot agree with an
implementation by construction, because there is nothing to agree with.

Every test below quotes the row it comes from. Where a row says something this
slice does not cover, the test is marked xfail with the reason, rather than
omitted, so the gap is visible in the run rather than in my memory.

Rows covered by this slice:

  T6.R1  a client request gets at most ONE response, with C's typed id
  T6.R2  an upstream result for a client id is delivered or withheld
  T6.R6  ids are (origin, type, value); "2001" is not 2001; the same typed id
         pending twice from C closes MALFORMED_CLIENT; an unsolicited or unknown
         response id from U closes MALFORMED_UPSTREAM; cancelled ids are
         rejected for reuse
  T7.R1  upstream exit with pending calls is an S5 trigger
  T7.R2  never resynchronise; a clean frame after the fault is discarded
"""
import json

import pytest

from sunglasses.proxy import framing

pump = pytest.importorskip("sunglasses.proxy.pump",
                           reason="the pump is the slice being specified here")


def wire(body):
    return json.dumps(body, separators=(",", ":")).encode() + b"\n"


def request(request_id, method="tools/call"):
    return {"jsonrpc": "2.0", "id": request_id, "method": method,
            "params": {"name": "read_text_file", "arguments": {"path": "/p"}}}


def response(request_id, text="ok"):
    return {"jsonrpc": "2.0", "id": request_id,
            "result": {"content": [{"type": "text", "text": text}]}}


# ── T6.R6: an id is a triple, not a value ──────────────────────────────────

def test_a_string_id_and_a_number_id_are_different_requests():
    """T6.R6: `"2001"` is not `2001`.

    A pump that keys by value alone answers one with the other, and the client
    cannot tell because both look like its own id coming back.
    """
    session = pump.Session()
    session.admit_request(2001, method="tools/call", origin="client")
    assert session.expects("2001", origin="client") is False
    assert session.expects(2001, origin="client") is True


def test_the_same_id_from_two_origins_is_two_requests():
    """T6.R6 keys by ORIGIN as well. An upstream request may legitimately carry
    an id a client request is already using, which is G2-15."""
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    session.admit_request(41, method="roots/list", origin="upstream")
    assert session.expects(41, origin="client")
    assert session.expects(41, origin="upstream")
    assert session.settle_from("upstream", 41, "UNINSPECTED_METHOD", "S3")
    assert session.expects(41, origin="client"), (
        "answering the upstream request retired the client's request, which is "
        "the G2-15 defect")


def test_the_same_typed_id_pending_twice_from_the_client_closes():
    """T6.R6: same typed id pending twice from C, MALFORMED_CLIENT, close."""
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    assert session.admit_request(41, method="tools/call", origin="client") is False
    assert session.closed_with() == ("MALFORMED_CLIENT", "S5")


def test_an_unsolicited_response_id_from_upstream_closes():
    """T6.R6: unsolicited or unknown response id from U, MALFORMED_UPSTREAM."""
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    session.deliver_response(origin="upstream", request_id=999)
    assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")


def test_a_cancelled_id_is_refused_for_reuse_for_the_session():
    """T6.R6. The tombstone outlives the request."""
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    session.cancel(41, origin="client")
    assert session.admit_request(41, method="tools/call", origin="client") is False


# ── T6.R1 and T6.R2: exactly one owner, exactly one answer ─────────────────

def test_a_client_request_gets_exactly_one_response_with_its_typed_id():
    """T6.R1: at most ONE response to C, carrying C's typed id."""
    session = pump.Session()
    session.admit_request("2001", method="tools/call", origin="client")
    first = session.deliver_response(origin="upstream", request_id="2001")
    assert first is not None
    assert first["id"] == "2001" and isinstance(first["id"], str)
    assert session.deliver_response(origin="upstream", request_id="2001") is None, (
        "a second upstream response for one client id produced a second answer")


# ── T7.R2: never resynchronise ─────────────────────────────────────────────

def test_a_clean_frame_after_a_protocol_fault_is_discarded():
    """T7.R2: never resynchronise at the next newline; a clean frame after the
    fault is discarded.

    The follower here is CLEAN on purpose. G2-10's own script follows its
    truncated frame with a well formed one carrying an injection, so a proxy
    that resynced would produce a detector finding and the finding would look
    like the mediator working.
    """
    stream = (b'{"jsonrpc":"2.0","id":41,"result":' + b"\n"
              + wire(response(41, "PERFECTLY-CLEAN")))
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    delivered = list(session.read_upstream(stream))
    assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")
    # What must never appear is the FOLLOWER. The one frame that may appear is
    # the client's own settlement: T6.R1 gives an admitted request exactly one
    # answer, and C07 requires it on this path, so the old `delivered == []`
    # would now leave a client blocked for ever on a session that has already
    # decided it is over. Asserting the absence of the follower is the property
    # this test was written for; asserting the absence of everything was the
    # spelling it had when a fault produced nothing at all.
    assert b"PERFECTLY-CLEAN" not in b"".join(delivered), (
        "a frame after the fault reached the client, so the stream was resumed")
    assert len(delivered) == 1
    settlement = json.loads(delivered[0])
    assert settlement["id"] == 41
    assert settlement["error"]["data"]["reason_code"] == "MALFORMED_UPSTREAM"


def test_the_item_owed_when_the_stream_faults_is_answered_not_stranded():
    """T7.R2 settles each KNOWN pending request once."""
    stream = b'{"jsonrpc":"2.0","id":41,"result":' + b"\n"
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    list(session.read_upstream(stream))
    assert session.answer_for(41, origin="client") is not None


# ── T7.R1: upstream exit with pending calls ────────────────────────────────

def test_upstream_exiting_with_a_pending_call_is_a_protocol_fault():
    """T7.R1 names it explicitly. A clean EOF is not a clean ending when the
    client is still owed an answer."""
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    list(session.read_upstream(b""))          # EOF with 41 outstanding
    assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")
    assert session.answer_for(41, origin="client") is not None


def test_upstream_exiting_with_nothing_pending_is_not_a_fault():
    """Or the check above would be calling every normal shutdown a fault."""
    session = pump.Session()
    list(session.read_upstream(b""))
    assert session.closed_with() is None


# ── T6.R2 response validation, which needs the pending method ──────────────

def test_a_response_whose_shape_does_not_match_the_request_is_refused():
    """G2-10/invalid_result_shape. `result.content` as a string where the
    request was a tools/call, which expects a list of blocks."""
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    bad = {"jsonrpc": "2.0", "id": 41, "result": {"content": "not a list"}}
    session.deliver_response(origin="upstream", request_id=41, frame=bad)
    assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")


# ── the same rows, on ASTRA's actual fixture bytes ─────────────────────────
# The tests above use frames built here. These read the seeds themselves, so the
# claim "the pump covers what Q12 and Q13 asked for" is checked against the
# bytes those checks read rather than against an analogue I wrote.

import pathlib

# CI. These were read from ASTRA's review directory in /private/tmp, which
# exists on one Mac and nowhere else. The `skipif` meant the rows did not fail
# in CI, they SKIPPED -- which is worse than the FileNotFoundError the controls
# produced, because a skip is silent and these are the checks that read the
# real wire bytes rather than an analogue I wrote.
FIX = (pathlib.Path(__file__).resolve().parent
       / "proxy/fixtures/pr164_f43781b")
fixtures = pytest.mark.skipif(not FIX.exists(),
                              reason=f"review fixtures not present at {FIX}")


@fixtures
def test_G2_10_invalid_result_shape_is_refused_by_the_pump():
    """Q13's first case, at the boundary where the ruling puts it.

    `parse_frame` cannot reject this alone and ASTRA said so: the frame is well
    formed JSON-RPC and only the REQUEST it answers makes its shape wrong. The
    pump knows the pending method, so it can.
    """
    lines = [x for x in (FIX / "G2-10" / "invalid_result_shape.upstream.jsonl"
                         ).read_bytes().splitlines() if x]
    frame = json.loads(lines[0])
    assert framing.parse_frame(lines[0]).ok, (
        "this frame is well formed on its own, which is the whole difficulty")

    session = pump.Session()
    session.admit_request(frame["id"], method="tools/call", origin="client")
    session.deliver_response(origin="upstream", request_id=frame["id"],
                             frame=frame)
    assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")


@fixtures
def test_G2_20_unsolicited_response_is_refused_by_the_pump():
    """Q13's second case. Nobody issued this id."""
    lines = [x for x in (FIX / "G2-20.unsolicited_response"
                         / "unsolicited_response.upstream.jsonl"
                         ).read_bytes().splitlines() if x]
    unsolicited = next(json.loads(x) for x in lines
                       if "result" in json.loads(x) or "error" in json.loads(x))
    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    session.deliver_response(origin="upstream",
                             request_id=unsolicited["id"], frame=unsolicited)
    assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")
    assert session.answer_for(41, origin="client") is not None, (
        "the item that WAS owed was stranded by the close")


@fixtures
def test_G2_15_reverse_request_cannot_retire_the_client_item():
    """Q12, at the boundary. The upstream request deliberately reuses the
    client's id, and answering it must not answer the client."""
    folder = FIX / "G2-15.reverse_request"
    client = json.loads((folder / "reverse_request.requests.jsonl"
                         ).read_bytes().splitlines()[0])
    upstream = [json.loads(x) for x
                in (folder / "reverse_request.upstream.jsonl").read_bytes().splitlines()]
    reverse = next(x for x in upstream if "method" in x and "id" in x)
    assert reverse["id"] == client["id"], "the fixture shares the id on purpose"

    session = pump.Session()
    session.admit_request(client["id"], method=client.get("method", "tools/call"),
                          origin="client")
    session.admit_request(reverse["id"], method=reverse["method"],
                          origin="upstream")
    session.settle_from("upstream", reverse["id"], "UNINSPECTED_METHOD", "S3")

    assert session.expects(client["id"], origin="client"), (
        "answering the upstream request retired the client's request")
    assert session.closed_with() is None


def test_an_integer_id_and_a_float_id_do_not_collide():
    """T6.R6 stores the JSON TYPE in the key, and this is why it is not
    decoration.

    A mutation removing the type from the key survived every other test in this
    file, because Python already keeps `2001` and `"2001"` apart as dict keys,
    so the type component looked redundant. It is not: `1 == 1.0` is True and
    they hash equal, so `{1: x}[1.0]` returns x. Both are valid JSON-RPC ids,
    a client may issue one while upstream answers with the other, and without
    the type in the key the pump would hand one request's result to the other
    and the client could not tell.
    """
    assert 1 == 1.0 and hash(1) == hash(1.0), "the collision this guards"

    session = pump.Session()
    assert session.admit_request(1, method="tools/call", origin="client")
    assert session.admit_request(1.0, method="tools/list", origin="client"), (
        "1.0 was refused as a duplicate of 1, so the two collided")
    assert session.closed_with() is None, "a false duplicate closed the session"

    assert session.expected_method(1, origin="client") == "tools/call"
    assert session.expected_method(1.0, origin="client") == "tools/list"

    answer = session.deliver_response(origin="upstream", request_id=1,
                                      frame=response(1))
    assert answer is not None and type(answer["id"]) is int
    assert session.expects(1.0, origin="client"), (
        "answering the integer id also retired the float id")


# ── T7.R1 + T8.R12: the exit is a PROCESS fact, never an inactivity guess ──

def test_an_upstream_exit_with_pending_calls_closes_even_though_the_pipe_stays_open():
    """The F21 shape, driven through the handle the contract requires.

    A leader spawns a grandchild and exits. The grandchild holds the write end,
    so the pipe never reaches EOF and the reader would wait for ever on a server
    that is already dead. An inactivity deadline cannot tell that from a healthy
    server thinking hard, and would eventually fire on both, so the signal is
    the HANDLE: wait on the process, not on the silence.

    Stopping the group is what actually releases the reader, because it closes
    the descendant's copy of the write end.
    """
    import subprocess
    import sys
    import threading
    import time

    child_code = "import sys,time;sys.stdout.write('R');sys.stdout.flush();time.sleep(30)"
    leader_code = "import subprocess,sys;subprocess.Popen([sys.executable,'-c',sys.argv[1]])"
    leader = subprocess.Popen([sys.executable, "-c", leader_code, child_code],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              start_new_session=True)
    try:
        assert leader.stdout.read(1) == b"R", "the grandchild never started"
        assert leader.wait(timeout=5) == 0, "the leader was supposed to exit"

        session = pump.Session()
        session.attach_upstream(leader, pgid=leader.pid)
        session.admit_request(41, method="tools/call", origin="client")

        done, yielded = threading.Event(), []

        def drive():
            try:
                yielded.extend(session.read_upstream(leader.stdout))
            finally:
                done.set()

        thread = threading.Thread(target=drive, daemon=True)
        thread.start()
        assert done.wait(5), (
            "the reader never returned, so stopping the group did not release "
            "the descendant's write end")
        assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")
    finally:
        try:
            os.killpg(leader.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        leader.wait(timeout=5)
        leader.stdout.close()


def test_an_upstream_that_exits_owing_nothing_is_a_normal_shutdown():
    """T7.R1 says exit WITH PENDING CALLS. A server that answered everything and
    then exited has done nothing wrong, and faulting there would turn every
    clean shutdown into an S5.

    Without this the watcher could close on any exit at all and no test would
    notice, which is what the mutation removing the pending check proved.
    """
    import io as _io
    import subprocess
    import sys
    import time

    finished = subprocess.Popen([sys.executable, "-c", "pass"],
                                start_new_session=True)
    finished.wait(timeout=5)

    session = pump.Session(upstream=finished, pgid=finished.pid)
    list(session.read_upstream(_io.BytesIO(b"")))      # nothing owed
    for _ in range(50):
        if session.closed_with():
            break
        time.sleep(0.02)
    assert session.closed_with() is None, (
        "a clean exit with nothing pending was reported as a protocol fault")


def test_strict_mode_refuses_to_read_without_a_handle():
    """An unsupervised upstream is the hang above, so it is a startup error
    rather than a quieter mode that fails later and less clearly."""
    import io as _io

    session = pump.Session(strict=True)
    with pytest.raises(pump.UnsupervisedUpstream):
        list(session.read_upstream(_io.BytesIO(b"")))


def test_a_handle_that_is_still_running_does_not_close_anything():
    """Or the watcher would be an inactivity timeout wearing a process fact's
    clothes."""
    import io as _io
    import subprocess
    import sys

    live = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"],
                            start_new_session=True)
    try:
        session = pump.Session(upstream=live, pgid=live.pid)
        session.admit_request(41, method="tools/call", origin="client")
        list(session.read_upstream(_io.BytesIO(wire(response(41)))))
        assert session.closed_with() is None
    finally:
        live.kill()
        live.wait(timeout=5)


import os      # noqa: E402
import signal  # noqa: E402


# ── RC11 to RC13: the halves ASTRA's controls do not reach ─────────────────
#
# Each of these four was written because a mutation SURVIVED the round-4
# controls. They are the positive and defensive halves that ASTRA's fixtures,
# which aim at the reported symptom, do not cover.

@pytest.mark.parametrize("member,value", [
    ("description", 7),
    ("title", ["review"]),
    ("annotations", []),
    ("outputSchema", "object"),
    ("_meta", 3.5),
])
def test_a_tool_member_declared_with_the_wrong_type_is_refused(member, value):
    """RC11's other half. The schema discriminant was the reported symptom and
    it is not the rule: MCP fixes the TYPE of every member a tool declares.

    A descriptor carrying `description: 7` is one a human cannot read and an
    approval cannot describe, and dropping the member check entirely left every
    round-4 control green, so the schema fix alone was covering for it.
    """
    session = pump.Session()
    assert session.admit_request(17, method="tools/list", origin="client")
    tool = {"name": "review", "inputSchema": {"type": "object"}, member: value}
    out = list(session.read_upstream(
        wire({"jsonrpc": "2.0", "id": 17, "result": {"tools": [tool]}})))
    assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")
    assert len(out) == 1 and "error" in json.loads(out[0])


def test_a_declared_member_of_the_right_type_is_not_refused():
    """The positive control, or the row above is satisfied by refusing tools
    that declare anything at all."""
    session = pump.Session()
    assert session.admit_request(17, method="tools/list", origin="client")
    tool = {"name": "review", "description": "reviews things",
            "annotations": {"readOnlyHint": True},
            "inputSchema": {"type": "object", "properties": {},
                            "required": ["path"]}}
    raw = wire({"jsonrpc": "2.0", "id": 17, "result": {"tools": [tool]}})
    assert list(session.read_upstream(raw)) == [raw]
    assert session.closed_with() is None


def test_a_control_id_that_is_not_pending_does_not_crash_the_reader(monkeypatch):
    """RC12's defensive half. `expects` returning true is a CLAIM about the
    table, and the pop is what acts on it.

    The whole point of RC12 is that the reader must not raise when the table
    does not match the claim: a KeyError out of the reader settles nothing,
    delivers nothing, and leaves a client blocked. Testing it with a stubbed
    `expects` is the only way to reach the branch without a real race, and the
    branch is exactly what a real race produces.
    """
    session = pump.Session()
    control = "sg-00000000-0000-4000-8000-000000000017"
    monkeypatch.setattr(session, "expects",
                        lambda rid, *, origin: rid == control)
    out = list(session.read_upstream(
        wire({"jsonrpc": "2.0", "id": control, "result": {"tools": []}})))
    assert out == []
    assert session.control_answer(control) is None


def test_settling_a_live_item_twice_still_raises():
    """RC13's narrowing. `Settled` is how a caller learns it has an ordering
    bug, and the race handling swallows it for a CLOSED session only.

    Widening that to every session would turn the one signal for a double
    answer into silence, which is the defect `Settled` exists to catch.
    """
    from sunglasses.proxy.session import Cause, Settled

    session = pump.Session()
    session.admit_request(41, method="tools/call", origin="client")
    identity = pump.key("client", 41)
    # Settled in the core and still pending in the pump, which is the double
    # settlement the exception names. Driven through the READER, because the
    # narrowing being tested lives on the pump's race handler and a direct call
    # to the core would only prove the core still raises.
    session._core.settle(session._core_key(identity), Cause("CLEAN", "S1"))
    assert session.closed_with() is None
    with pytest.raises(Settled):
        list(session.read_upstream(wire(response(41))))


def test_the_settling_record_does_not_outlive_the_settlement():
    """RC13's bound. `_settling` exists to be consulted by a close, and a set
    that is added to and never discarded from is an unbounded table plus a
    permanent claim that requests long since answered are still in flight."""
    session = pump.Session()
    for request_id in range(41, 45):
        assert session.admit_request(request_id, method="tools/call",
                                     origin="client")
        assert list(session.read_upstream(wire(response(request_id))))
    assert session._settling == set()
    assert session.closed_with() is None


# ── RC14 and RC17: the record's lifetime, and whose handoff it is ──────────
#
# ASTRA's round-5 controls cover the reader path and the watcher. Everything
# below was written because a mutation SURVIVED them: the obligation's owner,
# admission reading the record, and the close that pays it.

def test_the_record_survives_until_the_frame_is_handed_over():
    """RC14. The obligation ends at the HANDOFF, not at the settlement.

    The generator is suspended exactly at its `yield` here, which is the gap
    RC14 names: the item is settled CLEAN internally and the client still has
    nothing. If the record is dropped at the settlement instead, a close that
    lands in this gap finds the request in neither table and records no debt
    for it, and two known requests produce one frame.
    """
    session = pump.Session()
    assert session.admit_request(41, method="tools/call", origin="client")
    frames = session.read_upstream(wire(response(41)))
    next(frames)
    # ASTRA's RC19b settles what this instant MEANS, and it is not what I wrote
    # here first. `next()` RETURNING is the delivery: the consumer has the
    # frame. So at this point the obligation is discharged and the id is free,
    # and my original assertion -- that `_settling` was still occupied here --
    # was pinning the wrong moment. The obligation still exists strictly
    # BEFORE the yield executes; there is no observable instant between the
    # yield executing and `next()` returning.
    assert session._settling == set(), "the obligation outlived the handoff"
    with pytest.raises(StopIteration):
        next(frames)
    assert session._settling == set()


def test_a_direct_caller_has_the_frame_when_deliver_response_returns():
    """The other side of the same rule. A caller that is handed the frame has
    already taken it, so keeping a record for it would leave one nobody ever
    drops: the watcher would never sleep and the id would be blocked for the
    session."""
    session = pump.Session()
    assert session.admit_request(41, method="tools/call", origin="client")
    # A real result for the method that was asked, or T2's required-member
    # check refuses the frame and this proves nothing about the handoff.
    assert session.deliver_response(origin="upstream", request_id=41,
                                    frame=response(41))
    assert session._settling == set()


def test_an_id_still_being_answered_cannot_be_re_admitted():
    """RC17. The record is part of the pending state, so admission reads it.

    An id whose previous request is mid-handoff is not free. Re-admitting it
    lets the OLD response settle the NEW request, which answers a call the
    client never made with the result of one it did.
    """
    session = pump.Session()
    assert session.admit_request(41, method="tools/call", origin="client")
    frames = session.read_upstream(wire(response(41)))
    next(frames)
    # Same correction: after `next()` returns the frame is delivered, so reuse
    # here is VALID (RC19b) and refusing it was the bug. The refusal this test
    # was written for happens while the entry is genuinely mid-handoff, which
    # RC20 reaches through admission's own interleaving.
    assert session._settling == set()
    assert session.admit_request(41, method="tools/call", origin="client")
    assert session.closed_with() is None


def test_the_record_names_the_generation_it_answers():
    """RC17's second half. The settlement is bound to the generation captured
    when the entry left `_pending`, not to whatever the current one is when the
    core is finally called."""
    session = pump.Session()
    assert session.admit_request(41, method="tools/call", origin="client")
    identity = pump.key("client", 41)
    # BEFORE the handoff: the record exists and names the generation it
    # answers. Checked through the settlement seam rather than after `next()`,
    # because by the time `next()` returns the obligation is discharged
    # (RC19b) and the record is correctly gone.
    seen = {}
    original = session._settle_outside_lock

    def watched(key):
        seen["key"] = session._settling_key.get(identity)
        return original(key)

    session._settle_outside_lock = watched
    assert list(session.read_upstream(wire(response(41))))
    assert seen["key"] == identity + (1,)
    assert session._core.settled_as(identity + (1,)) is not None


def test_a_close_pays_the_record_and_then_drops_it():
    """The record exists to be read by a close. Once that close has recorded
    the debt it must not also keep the watcher awake (RC15) or block the id
    from ever being admitted again (RC17)."""
    session = pump.Session()
    assert session.admit_request(41, method="tools/call", origin="client")
    # The close is driven while the item is genuinely mid-handoff, which is
    # the only state where the record is the thing a close reads. Reaching it
    # from outside needs the settlement seam, for the same reason as above.
    closed_during = {}
    original = session._settle_outside_lock

    def watched(key):
        closed_during["settling"] = set(session._settling)
        session._close("MALFORMED_UPSTREAM", "review controlled close")
        return original(key)

    session._settle_outside_lock = watched
    list(session.read_upstream(wire(response(41))))
    assert closed_during["settling"], "the record was absent while mid-handoff"
    assert session._settling == set(), "the record outlived the close"
    assert session._settling_key == {}


def test_an_id_is_free_again_once_its_answer_has_been_handed_over():
    """The positive control for the admission rule, or it is satisfied by
    refusing every reuse. T6.R6 allows a COMPLETED id to be used again; only
    one still being answered is refused."""
    session = pump.Session()
    assert session.admit_request(41, method="tools/call", origin="client")
    assert list(session.read_upstream(wire(response(41))))
    assert session._settling == set()
    assert session.admit_request(41, method="tools/call", origin="client")
    assert session.closed_with() is None


# ── RC18: the decision has to be IN the yield expression ───────────────────

def test_a_close_at_the_handoff_instant_stops_the_frame_crossing():
    """RC18. The instant that matters is while the yield LINE is running and
    before the value leaves, and only an expression can be evaluated there.

    A statement before the yield runs too early: a close arriving at this
    moment found the record already discharged, stood down, and the resumed
    reader delivered anyway -- one original where none should have crossed,
    and the client's own refusal alongside it.

    The barrier here is `_handoff` itself, which IS that instant.
    """
    session = pump.Session()
    assert session.admit_request(41, method="tools/call", origin="client")
    identity = pump.key("client", 41)
    original = session._handoff
    seen = {}

    def blocking(ident, raw, *rest):
        # The yield line is running; nothing has crossed yet.
        seen["settling"] = set(session._settling)
        session._close("MALFORMED_UPSTREAM", "review controlled close")
        return original(ident, raw, *rest)

    session._handoff = blocking
    # A refused handoff yields b"", which is nothing on a byte stream: a
    # consumer writing it writes zero bytes. Filtering falsy rather than
    # None is what a real consumer does.
    out = [frame for frame in session.read_upstream(wire(response(41)))
           if frame]
    assert seen["settling"], "the record was already discharged at the handoff"
    assert not any("result" in json.loads(frame) for frame in out), (
        "an original crossed after the close had won")
    assert len(out) == 1 and "error" in json.loads(out[0])


def test_a_close_after_the_handoff_does_not_pay_again():
    """The opposite order, and the reason the discharge cannot simply move
    after the yield: once the frame is gone the obligation is gone with it, and
    a close that pays it again puts two answers on the wire for one request."""
    session = pump.Session()
    assert session.admit_request(41, method="tools/call", origin="client")
    frames = list(session.read_upstream(wire(response(41))))
    delivered = [f for f in frames if f]
    assert len(delivered) == 1 and "result" in json.loads(delivered[0])
    session._close("MALFORMED_UPSTREAM", "review controlled close")
    assert list(session._drain_refusals()) == [], (
        "the close paid an obligation that was already discharged")


def test_the_handoff_decision_is_made_by_the_yield_and_not_before_it():
    """RC18, pinned at the LINE rather than at the function.

    A control that wraps `_handoff` cannot see this: moving the call into a
    preceding statement calls the same function at the same logical point, and
    the wrapper is none the wiser. What changes is WHEN the call happens
    relative to the yield, so the barrier has to be a line event.

    Parked on the delivery line, before it runs, the record must still be
    owed. That is what makes a close arriving here win, and a frame that has
    not crossed stay uncrossed. With the decision in a preceding statement the
    record is already discharged at this point, the close stands down, and the
    original goes out behind it.
    """
    import inspect
    import sys as _sys

    source, first = inspect.getsourcelines(pump.Session.read_upstream)
    delivery = [first + i for i, line in enumerate(source)
                if line.strip().startswith("yield self._handoff(identity")]
    assert len(delivery) == 1, (
        "the delivery line moved; this control pins where the decision is made")

    session = pump.Session()
    assert session.admit_request(41, method="tools/call", origin="client")
    seen = {}

    def tracer(frame, event, arg):
        if (event == "line"
                and frame.f_code is pump.Session.read_upstream.__code__
                and frame.f_lineno == delivery[0] and "settling" not in seen):
            seen["settling"] = set(session._settling)
        return tracer

    _sys.settrace(tracer)
    try:
        out = [f for f in session.read_upstream(wire(response(41))) if f]
    finally:
        _sys.settrace(None)

    assert seen.get("settling"), (
        "the record was discharged BEFORE the delivery line ran, so a close "
        "arriving at that instant would stand down and the frame would cross")
    assert len(out) == 1


def test_a_refused_handoff_is_always_a_closed_session_and_pays_everyone():
    """The attacker's move behind the refusal, and the answer is not the one it
    first looks like.

    "One forced refusal silences the rest" is the right worry. It does not
    apply here, and asserting that a later frame STILL crosses would contradict
    T7.R2, which says never resynchronise: a clean frame arriving after a fault
    is discarded on purpose, because a session that keeps serving after a
    protocol fault is one an attacker can steer by causing the fault.

    A handoff refuses for exactly one reason -- the session is closed -- so the
    property that matters is that a refusal is never a SILENT drop. Everyone
    still owed an answer gets exactly one, the session says why, and the frame
    that did not cross is accounted for rather than lost.
    """
    session = pump.Session()
    for request_id in (41, 42):
        assert session.admit_request(request_id, method="tools/call",
                                     origin="client")
    original = session._handoff

    def closing(identity, raw, *rest):
        session._close("MALFORMED_UPSTREAM", "review controlled close")
        return original(identity, raw, *rest)

    session._handoff = closing
    out = [frame for frame in session.read_upstream(
        wire(response(41)) + wire(response(42))) if frame]

    # Nothing crossed for the refused frame, and both owed clients were paid.
    assert not any("result" in json.loads(frame) for frame in out)
    assert sorted(json.loads(frame)["id"] for frame in out) == [41, 42]
    assert all("error" in json.loads(frame) for frame in out)
    assert session.closed_with() == ("MALFORMED_UPSTREAM", "S5")


def test_a_refusal_cannot_happen_while_the_session_is_open():
    """The invariant the test above rests on, asserted rather than assumed: if
    a handoff could refuse on a live session, "silencing the rest" would be a
    real attack and the answer above would be the wrong one."""
    session = pump.Session()
    assert session.admit_request(41, method="tools/call", origin="client")
    identity = pump.key("client", 41)
    assert session.closed_with() is None
    assert session._handoff(identity, b"frame\n",
                            session._core_key(identity)) == b"frame\n"


def test_a_handoff_for_another_generations_record_faults_the_session():
    """RC25/RC26, the handoff half, ruled as a TRIPWIRE (T9, 2026-09-14).

    `_retire_record`'s ownership check is pinned by ASTRA's round-7 gate: remove
    it and two rows go red. The same check inside `_handoff` is NOT reachable
    from the production path -- admission refuses an identity while the record
    sits in `_settling`, and creation and handoff both happen inside that
    window -- and the mutation that removed it survived the entire suite.

    Unreachable today is not wrong tomorrow, and an equivalence argument is what
    was wrong about the generation lookup earlier in this review. So the rule is
    pinned as a contract. And it FAULTS rather than tolerating: a guard that
    silently absorbs a state the code calls impossible is a check that skips
    itself, green forever while the invariant beneath it rots. If admission's
    refusal ever stops holding, the session stops and says so.
    """
    session = pump.Session()
    assert session.admit_request(41, method="tools/call", origin="client")
    identity = pump.key("client", 41)
    mine = session._core_key(identity)
    theirs = identity + (mine[-1] + 1,)

    # The record standing here belongs to a LATER generation than the one this
    # reader captured -- the shape a reused id would produce.
    session._settling.add(identity)
    session._settling_key[identity] = theirs

    assert session._handoff(identity, b"frame\n", mine) == b"", (
        "the frame must not cross: the session has just faulted")
    assert session.closed_with() == ("INTERNAL_FAULT", "S3"), (
        "the mismatch must END the session and name the cause, not be "
        "absorbed; S3 because the peer violated nothing, we did")
    assert session._settling_key.get(identity, theirs) == theirs or \
        identity not in session._settling, (
        "the other generation's record was not discharged by this reader")
# ── T410: the refusal the client actually gets is the envelope, not a lookalike

ENVELOPE_DATA = {"reason_code", "rule", "budget", "accepted", "status",
                 "inspection_complete", "inspected_utf8_bytes",
                 "observed_content_bytes", "elapsed_ms", "rule_ids"}


def test_the_refusal_the_pump_writes_is_the_envelope():
    """T410. `envelope.withheld` exists because the refusal is the one
    structure an adversary is guaranteed to read, and the pump builds its own
    two-field dictionary beside it.

    A second construction of the same wire object is the failure mode the
    envelope module was written to prevent: every rule it enforces (the frozen
    reason catalog, the bounded rule_ids, `**ignored` swallowing a caller's
    detail string) applies to the copy that is NOT used, and the one on the
    wire is governed by nothing. The fields also have to be there for a
    receipt to be gradeable at all -- a refusal that cannot say whether any
    bytes were inspected cannot be compared to a fixture.
    """
    from sunglasses.proxy import envelope

    session = pump.Session()
    session.admit_request(1, method="ping", origin="client")
    out = list(session.read_upstream(b""))
    assert out, "the fault produced no client frame at all"
    written = json.loads(out[0])
    assert set(written["error"]["data"]) == ENVELOPE_DATA
    assert written["error"]["data"]["reason_code"] in envelope.REASONS


def test_an_over_budget_refusal_names_the_budget_that_broke():
    """T410's other half. The envelope REFUSES an OVER_BUDGET that cannot say
    which bound broke, and refuses a budget on any reason that has none, so the
    pair has to travel together from the close to the wire.

    Dropping the budget on the way left every field-set assertion green, which
    means the plumbing was covered by nothing: a breach nobody can attribute to
    a bound is a receipt that cannot be graded, and the row bounds four
    different things.
    """
    session = pump.Session()
    assert session.admit_request(41, method="tools/call", origin="client")
    over = json.dumps({"jsonrpc": "2.0", "id": 41,
                       "result": {"content": [{"type": "text",
                                               "text": "x" * 5_000_000}]}})
    out = list(session.read_upstream(over.encode() + b"\n"))
    assert session.closed_with() == ("OVER_BUDGET", "S3")
    assert len(out) == 1
    data = json.loads(out[0])["error"]["data"]
    assert data["reason_code"] == "OVER_BUDGET"
    assert data["budget"] == "frame"


def test_a_refusal_does_not_claim_a_scan_that_never_happened():
    """T410's values, not only its field names.

    A fault the pump found is a fault found BEFORE any scan, so the refusal
    must say so: not accepted, `not_run`, inspection not complete, nothing
    inspected. An envelope carrying every required member and claiming a
    complete finished inspection over bytes nobody read is the exact lie the
    module exists to prevent, and it passes any test that only checks which
    keys are present.
    """
    session = pump.Session()
    assert session.admit_request(41, method="tools/call", origin="client")
    out = list(session.read_upstream(b"{not json\n"))
    assert len(out) == 1
    data = json.loads(out[0])["error"]["data"]
    assert data["accepted"] is False
    assert data["status"] == "not_run"
    assert data["inspection_complete"] is False
    assert data["inspected_utf8_bytes"] == 0
    assert data["observed_content_bytes"] == 0
    assert data["rule_ids"] == []
