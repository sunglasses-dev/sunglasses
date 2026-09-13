"""Requirement 2: cancelling a request retires it, and the state survives the test.

ASTRA's `test_r2_helper_pending_retirement` asserts the id leaves `pending_ids()`
when `cancel` returns. This file covers that too, and then covers the thing his
exam explicitly says his own test cannot see.

His mutation calibration records one SURVIVOR: remove the cancellation state
while keeping its acknowledgement and the supplied requirement-2 test stays
green, because its terminal assertion is conditional on settlement existing. So
a proxy that says CANCEL_ACCEPTED, retires the id, and then settles the message
as though nothing had happened would pass the acceptance set. That is the worst
of the three possible bugs, because the acknowledgement is the part the client
reads.

The comment in `serve_stdio` already claimed `cancel` "drops the id from pending
and kills the worker". It did neither. Same family as every other defect found
today: the sentence describing the behaviour was written and the behaviour was
not.
"""
import pathlib
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from proxy.passthrough import Passthrough, REQUEST_CANCELLED   # noqa: E402


_CLEAN = ('print(__import__("json").dumps({"result": {"decision": "allow", '
          '"findings": [], "inspection_complete": True}}))')


def _worker(body):
    """A killable child, the way the proxy is actually used.

    My first version passed a plain function and the run tripped the watchdog,
    which is the harness telling the truth about my test rather than about the
    proxy. The scanner is an argv, and cancellation means killing a process.
    """
    return lambda _payload, _channel: [sys.executable, "-c", "import sys\n" + body]


_slow = _worker("sys.stdin.buffer.read()\nimport time\ntime.sleep(0.6)\n" + _CLEAN)


def _events(proxy, name, request_id):
    return [e for e in proxy.events
            if e.get("kind") == name and e.get("request_id") == request_id]


def test_cancelling_retires_the_id_the_moment_cancel_returns():
    """Not eventually, and not once the worker happens to finish.

    The window between the acknowledgement and the settlement is the whole
    question. A client told its request is cancelled, while this side still
    lists the id as in flight, is a proxy that disagrees with itself about what
    it is waiting for.
    """
    proxy = Passthrough(deadline_ms=2000, watchdog_ms=3000)
    proxy.submit("result", request_id="r2-retire", payload="x" * 32, scanner=_slow)
    assert proxy.await_hold_entered("r2-retire", timeout=1.0)

    proxy.cancel("r2-retire")

    assert "r2-retire" not in proxy.pending_ids(), (
        "the id was still pending after cancel returned")
    assert _events(proxy, "PENDING_RETIRED", "r2-retire"), (
        "retirement happened with no event, so no receipt can show it")


def test_the_acknowledgement_is_not_the_cancellation():
    """ASTRA's surviving mutation, made visible.

    Remove the state and keep the acknowledgement and his supplied test stays
    green. This one does not: the settled outcome has to say REQUEST_CANCELLED,
    unconditionally, because that is what the client is owed.
    """
    proxy = Passthrough(deadline_ms=2000, watchdog_ms=3000)
    held = proxy.submit("result", request_id="r2-ack", payload="x" * 32, scanner=_slow)
    assert proxy.await_hold_entered("r2-ack", timeout=1.0)

    proxy.cancel("r2-ack")
    outcome = held.result(timeout=3.0)

    assert _events(proxy, "CANCEL_ACCEPTED", "r2-ack"), "no acknowledgement at all"
    assert outcome.reason_code == REQUEST_CANCELLED, (
        f"acknowledged the cancellation and then settled {outcome.reason_code}")
    assert outcome.forwarded is False
    assert outcome.delivered_late is False


def test_cancelling_an_id_that_was_never_submitted_does_not_raise():
    """A proxy whose cancel path can crash is a proxy a client can crash.

    `cancel` indexed `_cancel_accepted[request_id]` directly, so a notification
    naming an id this side never held raised KeyError inside the pump. The
    upstream chooses the ids; being surprised by one is not an error condition.
    """
    proxy = Passthrough(deadline_ms=2000, watchdog_ms=3000)

    proxy.cancel("never-seen")

    assert _events(proxy, "CANCEL_ACCEPTED", "never-seen"), (
        "an unknown id should still be acknowledged, and recorded as unknown")
    assert not _events(proxy, "PENDING_RETIRED", "never-seen"), (
        "nothing was pending, so nothing was retired")
