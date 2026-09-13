"""The three seeds that must be able to fail the HARNESS, not a candidate.

G2-09 scanner hang, G2-10 malformed protocol, G2-11 cancelled request. A harness
that deadlocks, guesses its way back into sync, or delivers a held message late
would report those as candidate results, so they are written first and they are
written against the proxy itself.

Red-first: every test here failed before `proxy/` existed, and each one names the
property it is about rather than the implementation.
"""
import json
import pathlib
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from proxy import passthrough              # noqa: E402
from proxy.passthrough import (            # noqa: E402
    GATE2_WITHHELD_CODE, Decision, Passthrough, WatchdogTripped,
)

SCENARIOS = pathlib.Path.home() / ".claude" / "state" / "warroom" / "GATE2_SCENARIOS"


def _scenario(directory):
    return json.loads((SCENARIOS / directory / "scenario.json").read_text())


def _variant(directory, name):
    for variant in _scenario(directory)["variants"]:
        if variant["name"] == name:
            return variant
    raise AssertionError(f"{directory} has no variant {name!r}")


# ── G2-09: a stuck scanner must be killable, the loop must stay alive ───────

@pytest.mark.parametrize("direction", ["result", "request"])
def test_a_hung_scanner_is_terminated_and_the_loop_survives(direction):
    """The deadline belongs to the WORKER, never to the event loop.

    `sleep()` inside the forwarding loop would pass this by accident while making
    the proxy unable to answer anything else, so the test also sends a second
    message during the hang and requires an answer.
    """
    variant = _variant("09_scanner_hang", direction)
    proxy = Passthrough(deadline_ms=variant["deadline_ms"],
                        watchdog_ms=variant["watchdog_ms"])
    held = proxy.submit(direction, request_id=variant["request_id"],
                        payload="x" * 64, scanner=_hang)
    healthy = proxy.submit(direction, request_id=99, payload="ok", scanner=_instant)
    assert healthy.result(timeout=1.0).forwarded is True, (
        "the forwarding loop stopped answering while one scan was stuck")
    outcome = held.result(timeout=variant["watchdog_ms"] / 1000)
    assert outcome.forwarded is False
    assert outcome.worker_terminated is True, "the stuck worker was left running"
    assert variant["deadline_ms"] <= outcome.elapsed_ms <= variant["deadline_ms"] + 250, (
        f"terminal at {outcome.elapsed_ms} ms; the contract is the deadline plus "
        f"at most 250 ms of measured grace, and grace may not release payloads")


def test_the_withheld_error_preserves_the_request_id_and_its_json_type():
    """`"7"` and `7` are different ids. A proxy that normalises them mispairs."""
    proxy = Passthrough(deadline_ms=200, watchdog_ms=3000)
    for request_id in ("fault-9-result", 112, "112"):
        outcome = proxy.submit("result", request_id=request_id,
                               payload="x", scanner=_hang).result(timeout=2.0)
        message = outcome.replacement
        assert message["id"] == request_id and type(message["id"]) is type(request_id)
        assert message["error"]["code"] == GATE2_WITHHELD_CODE
        assert message["error"]["message"] == "GATE2_WITHHELD"


def test_the_withheld_error_carries_no_payload_and_no_exception_text():
    """`never_include` in every expected.json. A reason code, not a story."""
    secret = "SYNTHETIC-CANARY-b4d0c0ffee"
    proxy = Passthrough(deadline_ms=200, watchdog_ms=3000)
    outcome = proxy.submit("result", request_id=1, payload=secret,
                           scanner=_explode).result(timeout=2.0)
    rendered = json.dumps(outcome.replacement)
    assert secret not in rendered, "the withheld error leaked the payload it withheld"
    assert "Traceback" not in rendered and "RuntimeError" not in rendered
    assert outcome.replacement["error"]["data"]["reason_code"]


# ── the watchdog must fail the harness, not bless its silence ───────────────

def test_the_watchdog_fails_a_stuck_harness_rather_than_reporting_clean():
    """If the proxy itself wedges, that is a HARNESS fault and must be loud.

    A watchdog that merely stopped waiting would turn a broken harness into a
    scenario result, which is the failure this whole file exists to prevent.
    """
    proxy = Passthrough(deadline_ms=5000, watchdog_ms=300)
    stuck = proxy.submit("result", request_id=1, payload="x", scanner=_hang)
    with pytest.raises(WatchdogTripped) as tripped:
        stuck.result(timeout=2.0)
    assert "harness" in str(tripped.value).lower()


# ── G2-10: malformed protocol, and no guessing a resync ────────────────────

@pytest.mark.parametrize("line", [
    '{"jsonrpc": "2.0", "id": 1, "result":',          # truncated mid-object
    '{"jsonrpc": "2.0" "id": 1}',                     # missing comma
    'not json at all',
    '',                                               # an empty frame
])
def test_an_unparseable_frame_is_refused_without_resynchronising(line):
    proxy = Passthrough(deadline_ms=200, watchdog_ms=3000)
    verdict = proxy.read_frame(line)
    assert verdict.decision is Decision.REFUSE
    assert verdict.resynchronised is False, (
        "the proxy skipped ahead to the next frame it liked. Guessing where a "
        "stream resumes is how a mediator forwards half an attacker's message.")


def test_a_frame_over_the_wire_limit_is_refused_before_it_is_parsed():
    """A 4 MiB frame limit that only applies after json.loads is not a limit."""
    variant = _variant("09_scanner_hang", "result")
    limit = _scenario("09_scanner_hang")["setup"]["size_policy"]["wire_frame_byte_limit"]
    proxy = Passthrough(deadline_ms=200, watchdog_ms=3000, wire_frame_limit=limit)
    verdict = proxy.read_frame("{" + "a" * (limit + 10))
    assert verdict.decision is Decision.REFUSE
    assert verdict.parsed is False, "the oversized frame was parsed before refusal"


# ── G2-11: a held message whose request is cancelled is never delivered ────

def test_a_cancelled_request_never_delivers_its_held_message():
    proxy = Passthrough(deadline_ms=2000, watchdog_ms=3000)
    held = proxy.submit("result", request_id="fault-11-result",
                        payload="x" * 32, scanner=_slow)
    assert proxy.await_hold_entered("fault-11-result", timeout=1.0)
    proxy.cancel("fault-11-result")
    assert proxy.await_cancel_accepted("fault-11-result", timeout=1.0)
    outcome = held.result(timeout=3.0)
    assert outcome.forwarded is False
    assert outcome.delivered_late is False, (
        "the scan finished after cancellation and the result was delivered anyway")
    assert "fault-11-result" not in proxy.pending_ids(), "the id was never retired"


def test_a_cancelled_request_direction_forwards_nothing_upstream():
    """Zero upstream forwards, not merely an empty destination."""
    proxy = Passthrough(deadline_ms=2000, watchdog_ms=3000)
    held = proxy.submit("request", request_id="fault-11-request",
                        payload="x" * 32, scanner=_slow)
    assert proxy.await_hold_entered("fault-11-request", timeout=1.0)
    proxy.cancel("fault-11-request")
    held.result(timeout=3.0)
    assert proxy.upstream_forwards() == 0


def test_a_healthy_request_completes_while_another_is_cancelled():
    """The control. Cancellation must not be a way to stop the whole proxy."""
    proxy = Passthrough(deadline_ms=2000, watchdog_ms=3000)
    doomed = proxy.submit("result", request_id="fault-11-result",
                          payload="x", scanner=_slow)
    healthy = proxy.submit("result", request_id=112, payload="fine", scanner=_instant)
    proxy.await_hold_entered("fault-11-result", timeout=1.0)
    proxy.cancel("fault-11-result")
    assert healthy.result(timeout=2.0).forwarded is True
    assert doomed.result(timeout=3.0).forwarded is False


# ── the workers the tests drive the proxy with ─────────────────────────────
# argv, not callables, because that is what the scenario package specifies and
# what the real runs use: `["python3", "fault_worker.py", "hang"]`. A scanner
# that is a Python function in-process cannot be TERMINATED honestly, and an
# earlier draft that forked one drew a CPython warning about deadlocking a
# multi-threaded parent, inside the component whose job is to not deadlock.

_PY = sys.executable


def _worker(script):
    """A tiny argv worker. It reads the document on stdin like ASTRA's does."""
    return lambda _payload, _channel: [_PY, "-c", "import sys;" + script]


# A clean scan PRINTS a result, the way `fault_worker.py scan` does. A worker
# that exits 0 in silence is not a clean scan, it is an unreadable one, and the
# proxy now fails closed on it: deciding from the exit code alone let a payload
# the engine BLOCKED reach the model unchanged.
_CLEAN = ('print(__import__("json").dumps({"result": {"decision": "allow", '
          '"findings": [], "inspection_complete": True}}))')

_hang = _worker("sys.stdin.buffer.read()\nimport time\n"
                "while True: time.sleep(0.05)")
_slow = _worker("sys.stdin.buffer.read()\nimport time\ntime.sleep(0.6)\n" + _CLEAN)
_instant = _worker("sys.stdin.buffer.read()\n" + _CLEAN)
_blocks = _worker(
    'sys.stdin.buffer.read()\n'
    'print(__import__("json").dumps({"result": {"decision": "block", '
    '"findings": [{"id": "GLS-TEST-001"}], "inspection_complete": True}}))')
_silent = _worker("sys.stdin.buffer.read()")   # exits 0, says nothing
_explode = _worker(
    "sys.stdin.buffer.read()\n"
    "raise RuntimeError('worker failed with SYNTHETIC-CANARY-b4d0c0ffee inside')")


# ── the policy the proxy exists to apply ───────────────────────────────────
# The first live run forwarded a payload the pinned engine BLOCKS, because this
# file decided from the worker's EXIT CODE and never read what the scan said.
# `fault_worker.py scan` exits 0 whether it finds something or not, so a
# detector finding and a clean scan were the same event.

def test_a_detector_finding_withholds_the_message():
    proxy = Passthrough(deadline_ms=4000, watchdog_ms=6000)
    outcome = proxy.submit("result", request_id=7, payload="anything",
                           scanner=_blocks).result(timeout=5.0)
    assert outcome.forwarded is False
    assert outcome.reason_code == passthrough.PROHIBITED_CONTENT
    assert outcome.replacement["error"]["message"] == "GATE2_WITHHELD"
    # THE THREE FIELDS, SEPARATELY. This scan ran to the end and found what it
    # was looking for, so it is COMPLETE. `inspection_complete` used to be set
    # to `forwarded`, which filed this row as incomplete and made it
    # indistinguishable from a scanner that crashed before it looked.
    assert outcome.finding is True
    assert outcome.detector_status == passthrough.STATUS_COMPLETE
    assert outcome.inspection_complete is True
    assert outcome.rule_ids == ["GLS-TEST-001"]


def test_a_clean_scan_forwards():
    """The other half, or the check above could just withhold everything."""
    proxy = Passthrough(deadline_ms=4000, watchdog_ms=6000)
    outcome = proxy.submit("result", request_id=8, payload="anything",
                           scanner=_instant).result(timeout=5.0)
    assert outcome.forwarded is True
    assert outcome.reason_code == passthrough.CLEAN
    # Clean is a POSITIVE statement now, not the absence of one. A reason of
    # None cannot be compared against the package, which grades on CLEAN.
    assert outcome.finding is False
    assert outcome.detector_status == passthrough.STATUS_COMPLETE
    assert outcome.inspection_complete is True


def test_a_worker_that_says_nothing_is_uninspected_and_fails_closed():
    """Exit 0 in silence is not a clean scan. Unreadable means uninspected."""
    proxy = Passthrough(deadline_ms=4000, watchdog_ms=6000)
    outcome = proxy.submit("result", request_id=9, payload="anything",
                           scanner=_silent).result(timeout=5.0)
    assert outcome.forwarded is False
    assert outcome.reason_code == passthrough.INSPECTION_UNREADABLE
    # Not a finding, not complete, and not clean. All three have to be sayable
    # at once or this row reads like one of the other two.
    assert outcome.finding is False
    assert outcome.detector_status == passthrough.STATUS_UNREADABLE
    assert outcome.inspection_complete is False


# ── what gets inspected, measured on G2-01 before this existed ─────────────

def test_a_result_is_inspected_as_its_content_not_as_the_frame():
    """The envelope of a payload that BLOCKS scanned `allow` on the real engine.

    The injection sits inside a JSON string field and the frame around it reads
    as structure, so the mediator forwarded a message the detector would have
    stopped. Content, not envelope.
    """
    from proxy.passthrough import inspection_input
    frame = {"jsonrpc": "2.0", "id": 1, "result": {
        "content": [{"type": "text", "text": "GATE2_REPORT hostile body"}]}}
    leaves = inspection_input(frame, "result")
    assert [p for p, _ in leaves] == ["result.content[].text"]
    assert leaves[0][1] == "GATE2_REPORT hostile body"
    assert "jsonrpc" not in "\n".join(v for _p, v in leaves)


def test_a_request_is_inspected_as_its_argument_leaves_with_provenance():
    from proxy.passthrough import inspection_input
    frame = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "read_text_file",
        "arguments": {"path": "/tmp/a.txt", "opts": {"note": "second leaf"}}}}
    leaves = dict((p, v) for p, v in inspection_input(frame, "request"))
    assert leaves == {"params.arguments.path": "/tmp/a.txt",
                      "params.arguments.opts.note": "second leaf"}
    assert "tools/call" not in "\n".join(leaves.values()), (
        "the method name is frame structure and must not be inspected as content; "
        "scanning whole frames quarantined ordinary tools/call under GLS-MCP-002")


def test_a_frame_with_nothing_inspectable_yields_no_leaves():
    """A handshake has no payload to withhold; it must not be scanned as one."""
    from proxy.passthrough import inspection_input
    assert inspection_input({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                             "params": {"protocolVersion": "x"}}, "request") == []
    assert inspection_input({"jsonrpc": "2.0", "id": 0, "result": {}}, "result") == []


# ── G2-07: the budget that was accepted and never read ─────────────────────
# ASTRA measured 32,768 bytes forwarded under a budget of 1. `byte_budget` was
# stored by a constructor that nothing consulted, and the HOLD_ENTERED receipt
# recorded the byte count beside it, so the receipt looked like a bound was
# being applied. A bound that is configured, documented, recorded and not
# enforced is worse than no bound.

_SIZE_POLICY = _scenario("07_large_response")["setup"]["size_policy"]


def test_the_byte_budget_is_read_not_merely_accepted():
    """The exact measurement from the exam: a large payload, a budget of 1."""
    proxy = Passthrough(deadline_ms=4000, watchdog_ms=6000, byte_budget=1)
    outcome = proxy.submit("result", request_id="large-32768",
                           payload="x" * 32768, scanner=_instant).result(timeout=5.0)
    assert outcome.forwarded is False, (
        "32,768 bytes were forwarded under a byte budget of 1, which is what "
        "ASTRA measured on the live run")
    assert outcome.reason_code == passthrough.OVER_BYTE_BUDGET
    assert outcome.inspected_utf8_bytes == 32768
    assert outcome.inspection_complete is False
    assert outcome.finding is False


@pytest.mark.parametrize("variant,size,forwarded", [
    # The package's own three sizes against the package's own budget.
    ("bytes_32768", 32768, True),
    # INCLUSIVE at the budget, which the policy states and which is the
    # difference between `>` and `>=` in the only place it matters.
    ("bytes_262144", 262144, True),
    ("bytes_2097152", 2097152, False),
])
def test_the_package_sizes_land_where_the_policy_says(variant, size, forwarded):
    budget = _SIZE_POLICY["inspection_byte_budget"]
    assert _SIZE_POLICY["at_budget"] == "inclusive", "the policy changed"
    assert _variant("07_large_response", variant), variant
    proxy = Passthrough(deadline_ms=8000, watchdog_ms=12000, byte_budget=budget)
    outcome = proxy.submit("result", request_id=variant, payload="x" * size,
                           scanner=_instant).result(timeout=10.0)
    assert outcome.forwarded is forwarded, (
        f"{size} bytes against a budget of {budget}: forwarded="
        f"{outcome.forwarded}, reason {outcome.reason_code}")
    if not forwarded:
        assert outcome.reason_code == passthrough.OVER_BYTE_BUDGET


def test_an_over_budget_payload_never_reaches_a_worker():
    """The budget bounds the WORK, not just the answer.

    Scanning a document you have already decided to refuse spends the exact
    resource the budget exists to bound, so the refusal happens before the
    worker starts and no SCAN_STARTED is emitted for it.
    """
    proxy = Passthrough(deadline_ms=4000, watchdog_ms=6000, byte_budget=16)
    outcome = proxy.submit("result", request_id="nope", payload="y" * 4096,
                           scanner=_hang).result(timeout=5.0)
    assert outcome.reason_code == passthrough.OVER_BYTE_BUDGET
    started = [e for e in proxy.events
               if e["kind"] == "SCAN_STARTED" and e["request_id"] == "nope"]
    assert started == [], (
        "a worker was started for a payload already known to be over budget; "
        "note the scanner here HANGS, so this also proves the refusal does not "
        "wait for it")


# ── the reader itself is bounded, not just the frame it produced ───────────

def test_a_frame_with_no_newline_does_not_read_without_a_ceiling():
    """`readline` reads until a newline however far away it is.

    The wire limit was checked against the line it returned, which applies the
    bound AFTER the unbounded thing has already happened. An upstream that never
    sends a newline made the proxy allocate until it died, inside a component
    whose whole job is to survive a hostile upstream.
    """
    import io as _io

    limit = 4096
    # Ten times the limit, no newline anywhere in it.
    source = _io.BytesIO(b"x" * (limit * 10))
    frames = list(passthrough.bounded_lines(source, limit))
    assert frames, "the reader produced nothing at all"
    assert all(len(frame) <= limit + 1 for frame in frames), (
        f"a frame of {max(len(f) for f in frames)} bytes came back under a "
        f"limit of {limit}, so the ceiling is not being applied while reading")
    # And what it produced is refused through the ordinary path rather than
    # raising, so the refusal is recorded like every other refusal.
    proxy = Passthrough(wire_frame_limit=limit)
    verdict = proxy.read_frame(frames[0])
    assert verdict.decision is Decision.REFUSE
    assert verdict.resynchronised is False


def test_ordinary_framing_is_unchanged_by_the_ceiling():
    """Whole frames, split frames and a trailing frame with no newline."""
    import io as _io

    source = _io.BytesIO(b'{"a":1}\n{"b":2}\n{"c":3}')
    assert list(passthrough.bounded_lines(source, 1 << 20)) == [
        b'{"a":1}', b'{"b":2}', b'{"c":3}']


def test_the_frame_after_an_over_long_one_is_still_read():
    """The tail of a refused frame is dropped, the NEXT frame is not.

    Draining too little resumes inside the frame that was refused, which is the
    resynchronisation this harness refuses to do. Draining too much swallows a
    good message.
    """
    import io as _io

    limit = 64
    source = _io.BytesIO(b"z" * (limit * 4) + b'\n{"good":true}\n')
    frames = list(passthrough.bounded_lines(source, limit))
    assert frames[-1] == b'{"good":true}', frames


# ── item 6: receipts a stranger can grade ──────────────────────────────────

_CHATTY = _worker(
    "sys.stdin.buffer.read()\n"
    "sys.stderr.write('E' * 300000)\n"          # far past a pipe's ~64 KiB
    "sys.stderr.flush()\n" + _CLEAN)


def test_a_scanner_that_writes_a_lot_to_stderr_is_not_reported_as_a_deadline():
    """stderr was opened as a PIPE and never read.

    A pipe nobody drains fills at roughly 64 KiB and the writer BLOCKS, so a
    worker that logs enough hangs in `write` until the deadline kills it and the
    receipt says SCAN_DEADLINE about a scan that had finished thinking and was
    only trying to talk. The case where a scanner has the most to say is the
    case where it is in trouble, which is the case this used to misreport.
    """
    proxy = Passthrough(deadline_ms=4000, watchdog_ms=8000)
    outcome = proxy.submit("result", request_id="chatty", payload="x",
                           scanner=_CHATTY).result(timeout=7.0)
    assert outcome.reason_code == passthrough.CLEAN, (
        f"a talkative scanner was graded {outcome.reason_code}; it blocked on a "
        f"full stderr pipe rather than taking any real time")
    assert outcome.worker_terminated is False


def test_the_workers_own_account_of_a_failure_is_kept():
    """A scanner's explanation of why it failed is the first thing a stranger
    grading the run will want, and it was being discarded."""
    proxy = Passthrough(deadline_ms=4000, watchdog_ms=8000)
    proxy.submit("result", request_id="boom", payload="x",
                 scanner=_explode).result(timeout=7.0)
    output = [e for e in proxy.events if e["kind"] == "WORKER_OUTPUT"
              and e["request_id"] == "boom"]
    assert output, "no WORKER_OUTPUT event at all"
    assert "RuntimeError" in output[0]["stderr"], output[0]["stderr"][:200]
    assert output[0]["exit_code"] not in (0, None)
    assert output[0]["accepted"] is True, "it failed, but its output was read"


def test_a_discarded_worker_result_says_that_it_was_discarded():
    """Omitting a late result cannot be told from a worker that said nothing."""
    proxy = Passthrough(deadline_ms=300, watchdog_ms=6000)
    outcome = proxy.submit("result", request_id="late", payload="x",
                           scanner=_slow).result(timeout=5.0)
    assert outcome.reason_code == passthrough.SCAN_DEADLINE
    output = [e for e in proxy.events if e["kind"] == "WORKER_OUTPUT"
              and e["request_id"] == "late"]
    assert output and output[0]["accepted"] is False
    assert output[0]["discarded_reason"] == passthrough.SCAN_DEADLINE


def test_every_event_carries_a_monotonic_stamp_and_the_ids_json_type():
    """`time.time()` can step backwards when the host's clock is corrected, and
    a lifecycle read from it can show a scan settling before it started.

    And 4 and "4" are different JSON-RPC correlation ids that render
    identically in a receipt, while the replacement contract requires preserving
    the type rather than normalising it.
    """
    proxy = Passthrough(deadline_ms=4000, watchdog_ms=8000)
    proxy.submit("result", request_id=4, payload="x", scanner=_instant).result(timeout=5.0)
    proxy.submit("result", request_id="4", payload="x", scanner=_instant).result(timeout=5.0)

    assert all("mono" in e for e in proxy.events), "an event with no monotonic stamp"
    stamps = [e["mono"] for e in proxy.events]
    assert stamps == sorted(stamps), "the monotonic stamps are not ordered"

    typed = {(e["request_id"], e["request_id_type"]) for e in proxy.events
             if e["kind"] == "SETTLED"}
    assert (4, "int") in typed and ("4", "str") in typed, typed
