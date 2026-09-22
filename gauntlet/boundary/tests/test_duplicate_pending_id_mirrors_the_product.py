"""A client id reused while still pending is refused, as the product refuses it.

T8 measured the product on main 1e4e526 and I re-verified it at this head:
`sunglasses/proxy/session.py` refuses a request whose id is already in `_owed`
with ADMISSION_REFUSED reason `duplicate_pending_id`, tears down with
MALFORMED_CLIENT / ID_REUSED_WHILE_PENDING, and RETURNS BEFORE the assignment so
the pending entry is never overwritten.

The harness did none of that. `expect_upstream` wrote
`self._awaiting_upstream[request_id] = time.time()` unconditionally, so a
duplicate silently replaced the entry the first request owned — the exact
overwrite G2-20.duplicate_pending exists to catch. Mirrored here, so the
scenario has a subject.

THE CONTROL IS THE HALF THAT MATTERS: a DISTINCT id must still be admitted. A
refusal that fired on every second request would make this harness refuse every
healthy session, and the row would still look green against the duplicate.
"""
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from proxy import passthrough                                  # noqa: E402


def _proxy():
    return passthrough.Passthrough(deadline_ms=1000)


def test_a_reused_pending_id_is_refused_and_never_overwrites():
    proxy = _proxy()
    assert proxy.expect_upstream(2002) is True, "the first request must be admitted"
    first = dict(proxy._awaiting_upstream)

    assert proxy.expect_upstream(2002) is False, (
        "a second request carrying an id that is still pending must be refused")
    assert proxy._awaiting_upstream == first, (
        "the pending entry the first request owns was overwritten")

    reasons = [e.get("reason") for e in proxy.events
               if e["kind"] == "ADMISSION_REFUSED"]
    assert reasons == ["duplicate_pending_id"], proxy.events


def test_a_distinct_id_is_still_admitted():
    """The control. Without it a refusal that fired on everything would pass."""
    proxy = _proxy()
    assert proxy.expect_upstream(2002) is True
    assert proxy.expect_upstream(2003) is True, (
        "a DIFFERENT id is a different request and must still be admitted")
    assert set(proxy._awaiting_upstream) == {2002, 2003}
    assert not [e for e in proxy.events if e["kind"] == "ADMISSION_REFUSED"]


def test_an_id_that_was_answered_may_be_used_again():
    """Pending is the condition, not 'seen before'. Once the upstream has
    answered, the id is no longer owed and a later request may carry it."""
    proxy = _proxy()
    assert proxy.expect_upstream(2002) is True
    proxy.upstream_answered(2002)
    assert proxy.expect_upstream(2002) is True, (
        "the id was no longer pending, so this is not a reuse-while-pending")
