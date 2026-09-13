"""The real stdio adapter, driven through pipes with real worker processes.

Everything else in this directory drives `Passthrough` directly. That is the
right shape for policy questions and the wrong shape for these two, because both
of the faults below live in `serve`'s pump and are INVISIBLE from the helper:

  the pump called `.result()` inline, so it could not read the next frame until
  the current scan settled. A cancellation for the message being scanned queued
  up behind the scan it was meant to cancel, and a healthy request sat behind a
  hung one.

  notifications were forwarded on the strength of having no `id`, so
  `notifications/cancelled` went upstream and the proxy never learned of it.
  Nothing on that path ever called `cancel`.

All 77 tests in this directory passed with both faults in place.
"""
import json
import pathlib
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from proxy import passthrough                                  # noqa: E402
from proxy.passthrough import serve                            # noqa: E402

_PY = sys.executable

# An upstream that answers every tools/call with a content result and never
# stalls, so anything slow in a test below is the SCANNER and not the server.
_UPSTREAM = [
    _PY, "-c",
    "import sys, json\n"
    "for line in sys.stdin:\n"
    "    line = line.strip()\n"
    "    if not line: continue\n"
    "    msg = json.loads(line)\n"
    "    if msg.get('id') is None: continue\n"
    "    out = {'jsonrpc': '2.0', 'id': msg['id'], 'result': {'content': ["
    "        {'type': 'text', 'text': 'UPSTREAM-' + str(msg['id'])}]}}\n"
    "    sys.stdout.write(json.dumps(out) + '\\n'); sys.stdout.flush()\n"
]

# Scanners as ARGV, because `serve` takes argv and appends --channel.
_SCAN_CLEAN = [_PY, "-c",
               "import sys, json\n"
               "sys.argv\n"
               "sys.stdin.buffer.read()\n"
               "print(json.dumps({'result': {'decision': 'allow', 'findings': [],"
               " 'inspection_complete': True}}))"]
# Hangs only for the payload that carries the marker, so one id can stall while
# another goes through the same proxy in the same run.
_SCAN_HANG_ON_MARKER = [
    _PY, "-c",
    "import sys, json, time\n"
    "body = sys.stdin.buffer.read().decode('utf-8', 'replace')\n"
    "if 'STALL-ME' in body:\n"
    "    time.sleep(600)\n"
    "print(json.dumps({'result': {'decision': 'allow', 'findings': [],"
    " 'inspection_complete': True}}))"]


class _Proxy:
    """`serve` on a thread, talking over os pipes like the real thing."""

    def __init__(self, tmp_path, scanner_argv, **kwargs):
        import os
        self._c_r, self._c_w = os.pipe()          # client -> proxy stdin
        self._p_r, self._p_w = os.pipe()          # proxy stdout -> client
        self.receipts = tmp_path / "receipts.jsonl"
        self._stdin = os.fdopen(self._c_r, "rb")
        self._to_proxy = os.fdopen(self._c_w, "wb")
        self._stdout = os.fdopen(self._p_w, "wb")
        self._from_proxy = os.fdopen(self._p_r, "rb")
        self._thread = threading.Thread(
            target=serve, daemon=True,
            args=(_UPSTREAM, scanner_argv),
            kwargs=dict(receipts=str(self.receipts), stdin=self._stdin,
                        stdout=self._stdout, **kwargs))
        self._thread.start()

    def send(self, message):
        self._to_proxy.write((json.dumps(message) + "\n").encode())
        self._to_proxy.flush()

    def read_until(self, wanted_ids, timeout=12.0):
        """Every line the client receives, until all `wanted_ids` have arrived."""
        seen, deadline = {}, time.monotonic() + timeout
        while time.monotonic() < deadline and set(wanted_ids) - set(seen):
            line = self._from_proxy.readline()
            if not line:
                break
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if message.get("id") is not None:
                seen[message["id"]] = message
        return seen

    def close(self):
        try:
            self._to_proxy.close()
        except OSError:
            pass
        self._thread.join(timeout=12.0)

    def events(self):
        if not self.receipts.exists():
            return []
        return [json.loads(line) for line in
                self.receipts.read_text().splitlines() if line.strip()]


def _call(request_id, text):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": "write_file",
                       "arguments": {"path": "/tmp/x", "content": text}}}


def test_a_healthy_request_is_answered_while_another_is_stuck(tmp_path):
    """Head of line blocking, on the real adapter.

    111 stalls its scanner forever. 112 is ordinary and is sent AFTER it. With
    the pump waiting inline on each scan, 112 cannot even be READ until 111's
    deadline expires, so this is the test that distinguishes a mediator from a
    queue.
    """
    proxy = _Proxy(tmp_path, _SCAN_HANG_ON_MARKER, deadline_ms=8000,
                   watchdog_ms=20000)
    try:
        proxy.send(_call(111, "STALL-ME please"))
        proxy.send(_call(112, "ordinary content"))
        seen = proxy.read_until([112], timeout=6.0)
    finally:
        proxy.close()

    assert 112 in seen, (
        "the healthy request was never answered while another was stuck, which "
        "is head of line blocking and not mediation")
    # And it came back within the stuck scan's deadline, not after it.
    assert 111 not in seen, "111 should still have been stuck at this point"


def test_a_cancellation_notification_actually_cancels(tmp_path):
    """`notifications/cancelled` has no id of its own and used to pass straight
    through, so the proxy never heard about it."""
    proxy = _Proxy(tmp_path, _SCAN_HANG_ON_MARKER, deadline_ms=20000,
                   watchdog_ms=30000)
    try:
        proxy.send(_call(111, "STALL-ME please"))
        # Wait until the scan is genuinely running, so this cannot pass by
        # cancelling something that had already settled.
        for _ in range(200):
            if any(e.get("kind") == "SCAN_STARTED" for e in proxy.events()):
                break
            time.sleep(0.05)
        else:
            pytest.fail("the scan never started, so nothing was cancelled")
        proxy.send({"jsonrpc": "2.0", "method": "notifications/cancelled",
                    "params": {"requestId": 111}})
        for _ in range(200):
            if any(e.get("kind") == "CANCEL_ACCEPTED" for e in proxy.events()):
                break
            time.sleep(0.05)
    finally:
        proxy.close()

    events = proxy.events()
    accepted = [e for e in events if e.get("kind") == "CANCEL_ACCEPTED"]
    assert accepted, (
        "no CANCEL_ACCEPTED: the notification was forwarded upstream and the "
        "proxy never learned of it, which is the state G2-11 ran in")
    assert accepted[0].get("request_id") == 111

    settled = [e for e in events if e.get("kind") == "SETTLED"
               and e.get("request_id") == 111]
    if settled:
        assert settled[0].get("reason") == passthrough.REQUEST_CANCELLED, settled[0]


def test_a_cancelled_request_is_never_released_to_the_upstream(tmp_path):
    """Late output must be discarded. A worker that finishes after the
    cancellation must not be able to release anything."""
    proxy = _Proxy(tmp_path, _SCAN_HANG_ON_MARKER, deadline_ms=20000,
                   watchdog_ms=30000)
    try:
        proxy.send(_call(111, "STALL-ME please"))
        for _ in range(200):
            if any(e.get("kind") == "SCAN_STARTED" for e in proxy.events()):
                break
            time.sleep(0.05)
        proxy.send({"jsonrpc": "2.0", "method": "notifications/cancelled",
                    "params": {"requestId": 111}})
        for _ in range(200):
            if any(e.get("kind") == "CANCEL_ACCEPTED" for e in proxy.events()):
                break
            time.sleep(0.05)
        seen = proxy.read_until([111], timeout=2.0)
    finally:
        proxy.close()

    assert 111 not in seen or seen[111].get("error"), (
        f"a cancelled request delivered its held message: {seen.get(111)}")


def test_an_ordinary_session_still_works_end_to_end(tmp_path):
    """The concurrency change must not have cost the plain path.

    Without this, every test above would pass just as well for a proxy that
    answered nothing at all.
    """
    proxy = _Proxy(tmp_path, _SCAN_CLEAN, deadline_ms=8000, watchdog_ms=20000)
    try:
        proxy.send(_call(201, "harmless"))
        proxy.send(_call(202, "also harmless"))
        seen = proxy.read_until([201, 202], timeout=10.0)
    finally:
        proxy.close()

    assert set(seen) == {201, 202}, seen
    for request_id in (201, 202):
        assert seen[request_id]["result"]["content"][0]["text"] == \
            f"UPSTREAM-{request_id}", seen[request_id]
