"""The per-id tables a session keeps do not grow with requests that are over.

`Session` kept state per id that only grew, and the client controls how many
ids there are:

  - a table of ids that had been answered, which nothing ever read;
  - the time each request was admitted, read only while it is pending;
  - the cancel marks, which `notifications/cancelled` added to for any id the
    client named, whether or not a request with that id had ever been admitted;
  - a set of the same kind on the route.

The first two are now dropped when a request leaves the pending table, and a
cancel for an id that was never admitted names nothing and records nothing.
The generation counter and the record of final answers are kept for the life of
the session on purpose (a late frame for an earlier use of an id must not be
mistaken for the current one) and are not asserted here.
"""
import io

from route_harness import call_request, frame, make_route

N = 500


def _complete(engine, request_id):
    engine.client_frame(call_request(request_id))
    engine.pump_upstream(io.BytesIO(frame(
        id=request_id, result={"content": [{"type": "text", "text": "ok"}]})))


def test_completed_requests_leave_no_admission_time_behind(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path)
    for i in range(N):
        _complete(engine, i)
    assert engine.session.closed_with() is None
    assert len(client.writes) == N
    assert len(engine.session._admitted_at) == 0


def test_a_pending_request_keeps_its_admission_time(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path)
    engine.client_frame(call_request(1))
    assert len(engine.session._admitted_at) == 1
    engine.pump_upstream(io.BytesIO(frame(
        id=1, result={"content": [{"type": "text", "text": "ok"}]})))
    assert len(engine.session._admitted_at) == 0


def test_cancels_of_ids_that_were_never_admitted_record_nothing(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path)
    for i in range(N):
        engine.client_frame(frame(method="notifications/cancelled",
                                  params={"requestId": 10_000_000 + i}))
    assert engine.session.closed_with() is None
    assert len(engine.session._cancelled_ids) == 0
    assert len(engine.session._cancelled_at) == 0


def test_a_cancel_sent_before_its_id_is_used_does_not_touch_the_later_request(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path)
    engine.client_frame(frame(method="notifications/cancelled",
                              params={"requestId": 7}))
    _complete(engine, 7)
    assert engine.session.closed_with() is None
    answers = client.messages()
    assert len(answers) == 1
    assert answers[0]["id"] == 7 and "result" in answers[0]
    assert upstream.bytes, "the call was not forwarded"


def test_a_cancel_for_an_admitted_request_is_still_honoured(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path)
    engine.client_frame(call_request(3))
    engine.client_frame(frame(method="notifications/cancelled",
                              params={"requestId": 3}))
    answers = client.messages()
    assert len(answers) == 1 and answers[0]["id"] == 3
    assert len(engine.session._cancelled_ids) == 1
