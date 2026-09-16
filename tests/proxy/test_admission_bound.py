"""T8.R6, the admission bound, as its own subject.

The contract table says `in-flight held messages + pending forwarded requests
(outstanding correlations) / queued bytes | 8 / 16 MiB | S3 OVERLOADED on the
NEW item per T6.R7; held items never dropped`. `bounds.check_admission` has
implemented both halves since it was written and NOTHING ASKED IT: the pump
admitted a ninth correlation and a request behind a full write queue, so the
row was a table entry rather than a bound.

These rows arrived in the result-direction PR because that is where the work
happened. ASTRA's RD09 measured the change there and read it as a regression --
the base admits nine, the candidate admits eight -- which is the base being
unbounded rather than the candidate being wrong. T9 ruled it out of that PR and
into this one, where the contract row is the subject and can be reviewed as
one, and where "the body equals the delta" is true by construction.

The queued-byte half of the same row is NOT here: it reads `queued_bytes`, an
attribute the write queue owns, which arrives with #168. It is named in the PR
body as owed rather than quietly dropped.
"""
import pytest

from sunglasses.proxy import bounds, pump


def test_the_eighth_outstanding_request_is_still_admitted():
    """Eight is the cap, not seven. A bound that refuses AT the limit is a
    different promise from one that refuses past it, and this one counts items
    already held -- so the eighth is the last one in, not the first one out."""
    session = pump.Session()
    for request_id in range(bounds.OUTSTANDING):
        assert session.admit_request(request_id, method="ping", origin="client"), (
            f"request {request_id} was refused below the cap of {bounds.OUTSTANDING}")


def test_the_ninth_outstanding_request_is_refused():
    """T801. The ninth is the one the table forbids, and refusing the NEW item
    is T6.R7: a held message is never dropped to make room, because dropping
    one withdraws an answer somebody is already waiting for."""
    session = pump.Session()
    for request_id in range(bounds.OUTSTANDING):
        assert session.admit_request(request_id, method="ping", origin="client")
    assert not session.admit_request(bounds.OUTSTANDING, method="ping",
                                     origin="client")


def test_the_refusal_is_recorded_as_overloaded():
    """A refusal nobody can see in the receipts is a session that silently
    stops accepting work. The emit carries the reason the table names."""
    session = pump.Session()
    seen = []
    original = session._core._emit
    session._core._emit = lambda event, *a, **k: (
        seen.append((event, k.get("reason"))), original(event, *a, **k))[1]
    for request_id in range(bounds.OUTSTANDING):
        assert session.admit_request(request_id, method="ping", origin="client")
    assert not session.admit_request(99, method="ping", origin="client")
    assert ("ADMISSION_REFUSED", "OVERLOADED") in seen, seen


def test_an_upstream_request_is_not_counted_against_the_client_cap():
    """The row counts CLIENT correlations. Counting upstream's own requests
    against the same cap would let a chatty server close the client's window,
    which is the opposite of what a bound on admission is for."""
    session = pump.Session()
    for request_id in range(bounds.OUTSTANDING):
        assert session.admit_request(request_id, method="ping", origin="client")
    # The client cap is full; upstream's namespace is its own.
    assert session.admit_request(1, method="ping", origin="upstream")


def test_an_upstream_correlation_does_not_consume_the_client_cap():
    """The distinguishing control, and the reason it exists is worth writing
    down: the row above cannot separate "count client correlations" from "count
    everything", because an upstream admission skips the cap entirely either
    way. Only a session holding BOTH can tell them apart.

    One upstream request outstanding, then the client's full eight. If the
    count is of everything, the eighth client is refused by a correlation the
    client did not make -- a server that keeps one request open would
    permanently cost the client a slot.
    """
    session = pump.Session()
    assert session.admit_request(1, method="ping", origin="upstream")
    for request_id in range(bounds.OUTSTANDING):
        assert session.admit_request(request_id, method="ping", origin="client"), (
            f"client request {request_id} was refused with an upstream "
            f"correlation outstanding; the cap is counting the wrong things")
    assert not session.admit_request(bounds.OUTSTANDING, method="ping",
                                     origin="client")
