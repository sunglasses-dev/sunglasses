"""The row for pump.py hunk 3, the one the merge could have shipped.

R-168-R9 + R-179-R7, merge boundary. Neither parent can host this row: the
obligation table `_unanswered` is #168 r9's, and `breach`/`reserved` are #179's,
so the defect exists only where the two meet. That is exactly why a merge wants
a row and not a paragraph.

THE PROPERTY. `bounds.check_admission` is origin-independent -- it compares
`outstanding >= OUTSTANDING` -- so a CLIENT request arriving at the cap is
refused for overload. A refused admission sets no `_pending` entry, is never
admitted to the core, and no frame is ever generated for it. So it must not be
recorded as an outstanding obligation. `_unanswered` outlives retirement BY
DESIGN, which is the whole point of r9, so an entry made here is never
discharged by anything: the session would owe a wire answer for ever for a
request it refused, and the teardown would report it.

RED on the textual union of the two parents (r9's two writes left where they
stood, above #179's breach branch). GREEN on the resolution that moves them
inside the `else:`.
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from sunglasses.proxy import bounds, pump  # noqa: E402


def _admit(session, request_id):
    return session.admit_request(request_id, method="tools/call",
                                 origin=pump.ORIGIN_CLIENT)


def test_an_overload_refused_client_request_owes_nothing():
    session = pump.Session()

    for request_id in range(1, bounds.OUTSTANDING + 1):
        assert _admit(session, request_id) is True, request_id

    owed_before = set(session.unanswered_clients())
    assert len(owed_before) == bounds.OUTSTANDING

    # The one that breaches. Refused, so nothing about it is outstanding.
    assert _admit(session, "over-the-cap") is False

    owed_after = set(session.unanswered_clients())
    leaked = owed_after - owed_before
    assert not leaked, (
        f"an overload-refused client request left {len(leaked)} obligation(s) "
        f"nothing can ever discharge: {sorted(map(str, leaked))}. `_pending` was "
        f"never set for it, the core never admitted it and no frame will be "
        f"generated, but `_unanswered` outlives retirement -- so the session now "
        f"owes a wire answer for a request it refused.")
    assert owed_after == owed_before


def test_the_refusal_is_still_a_refusal():
    """Guard against fixing the leak by not refusing. The cap must still bite."""
    session = pump.Session()
    for request_id in range(1, bounds.OUTSTANDING + 1):
        assert _admit(session, request_id) is True
    assert _admit(session, "over-the-cap") is False
    assert len(set(session.unanswered_clients())) == bounds.OUTSTANDING
