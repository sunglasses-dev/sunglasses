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


_hang = _worker("sys.stdin.buffer.read()\nimport time\n"
                "while True: time.sleep(0.05)")
_slow = _worker("sys.stdin.buffer.read()\nimport time\ntime.sleep(0.6)")
_instant = _worker("sys.stdin.buffer.read()")
_explode = _worker(
    "sys.stdin.buffer.read()\n"
    "raise RuntimeError('worker failed with SYNTHETIC-CANARY-b4d0c0ffee inside')")
