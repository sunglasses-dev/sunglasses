"""The proxy's own request and answer channel, T2.R6 and T6.R6.

Written against `tests/test_proxy_control_channel.py`, committed first.

The core's seam gives the proxy an id namespace and a hand-off dict that the
reader fills without ever blocking. This is the other side of it: it issues a
request in that namespace and waits for the answer to appear.

It is the ONLY place in this package where one thread waits on another, so both
of its rules are about not becoming a deadlock.

It never waits forever. The thread waiting here is the one serving the client's
call, and a server that simply stops answering would otherwise hold it for as
long as it liked. Every wait has a deadline and a miss is a named fault. A
session that has already torn down ends the wait at once, because an answer can
no longer arrive and waiting out the deadline there is a guaranteed wait for
nothing.

And it never waits ON THE READER. The reader assigns and moves on; this side
polls. A rendezvous where each side waits for the other is the shape that
stalls the pump, and the pump is the thing that notices the upstream dying.

Polling rather than a condition variable is deliberate. A condition needs the
reader to notify, which means the reader has to know this side exists, and the
one property the seam is built on is that the reader hands over and is done.
"""
from __future__ import annotations

import json
import time
import uuid

from .pump import CONTROL_PREFIX, ORIGIN_PROXY

DEADLINE_MS = 10_000          # T8.R13's whole-list bound, per request here
POLL_S = 0.005


class ControlTimeout(RuntimeError):
    """The answer did not arrive, or cannot any more. Never a hang."""


class Control:
    def __init__(self, *, session, upstream_write, deadline_ms=DEADLINE_MS,
                 now=None, sleep=None):
        self.session = session
        self.upstream_write = upstream_write
        self.deadline_ms = deadline_ms
        self._now = now or (lambda: time.monotonic() * 1000.0)
        self._sleep = sleep or time.sleep

    def send(self, method, params=None):
        """Issue one request in the proxy's namespace and return its id."""
        request_id = CONTROL_PREFIX + uuid.uuid4().hex
        self.session.admit_request(request_id, method=method,
                                   origin=ORIGIN_PROXY)
        frame = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params:
            frame["params"] = params
        self.upstream_write(
            (json.dumps(frame, separators=(",", ":")) + "\n").encode("utf-8"))
        return request_id

    def await_answer(self, request_id):
        """The result the reader dropped in, or ControlTimeout."""
        started = self._now()
        while True:
            answer = self.session.control_answer(request_id)
            if answer is not None:
                if "error" in answer:
                    raise ControlTimeout(
                        f"the server refused the control request: "
                        f"{answer['error'].get('code')}")
                return answer.get("result")
            if self.session.closed_with():
                # No answer can arrive on a torn-down session. Sitting out the
                # deadline here is a wait we already know the outcome of.
                raise ControlTimeout("the session closed before the answer")
            if self._now() - started > self.deadline_ms:
                raise ControlTimeout(
                    f"no answer within {self.deadline_ms} ms")
            self._sleep(POLL_S)

    def pager(self, method):
        """`pager(cursor)` issues one page and returns its result.

        The shape `snapshot.collect` takes, so the collector knows nothing
        about transport, ids or threads.
        """
        def request(cursor):
            params = {"cursor": cursor} if cursor else {}
            return self.await_answer(self.send(method, params))
        return request
