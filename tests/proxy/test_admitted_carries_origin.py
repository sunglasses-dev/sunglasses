"""ADMITTED named the id TYPE and not WHO AUTHORED the request.

The proxy knows the origin at that exact moment -- it is part of the identity
key (`pump.key()` is origin, JSON type, value) and it is passed into
`admit_request` a few lines above the record. It was known and dropped, so an
auditor reading ADMITTED could not tell a client call from an upstream-authored
one. `FRAME_IN` carries `direction`, which is the hop, not the author.

The vocabulary is checked BEFORE the field is emitted anywhere, because the
first record to carry origin would otherwise also be the first that could carry
a fourth spelling of it.
"""
import json
import pathlib

import pytest

from sunglasses.proxy import framing, pump, receipts, route


def test_the_three_origins_are_one_definition_not_three_copies():
    """`route` had its own CLIENT/UPSTREAM, equal by value and nothing keeping
    them equal. They are the same objects now."""
    assert route.CLIENT is pump.ORIGIN_CLIENT
    assert route.UPSTREAM is pump.ORIGIN_UPSTREAM


def test_framings_default_origin_has_not_drifted():
    """`framing` CANNOT import `pump` -- pump imports framing, so binding them
    would be a cycle. One definition is not available here, so drift is caught
    instead of prevented, which is the honest second best.
    """
    import inspect as _inspect
    default = _inspect.signature(framing.parse_frame).parameters["origin"].default
    assert default == pump.ORIGIN_UPSTREAM, (
        f"framing.parse_frame defaults origin to {default!r} while pump calls "
        f"it {pump.ORIGIN_UPSTREAM!r}; they are separate literals by necessity "
        f"and this row is the only thing keeping them equal")


@pytest.mark.parametrize("good", ["client", "proxy", "upstream", None])
def test_every_real_origin_is_accepted(good):
    assert receipts._check_value("origin", good) is None


@pytest.mark.parametrize("bad", ["Client", "server", "", "CLIENT", 5, True])
def test_a_spelling_outside_the_vocabulary_RAISES(bad):
    """Not trimmed, not coerced. A receipt is read as a record of what
    happened, so a wrong origin is a false fact rather than a cosmetic one."""
    with pytest.raises(ValueError):
        receipts._check_value("origin", bad)


def test_the_admitted_record_carries_origin_to_disk(tmp_path):
    """The read-back. A field permitted in memory can still be dropped by
    `_clean` on the way to the file -- this repository has measured that once
    already with `cause_kind`."""
    log = receipts.Log(tmp_path, run_id="t-origin", header={})
    log.event("ADMITTED", id_type="int", origin=pump.ORIGIN_CLIENT)
    rows = []
    for path in sorted((tmp_path / "receipts").glob("*.jsonl")):
        rows += [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    admitted = [r for r in rows if r.get("kind") == "ADMITTED"]
    assert admitted, f"no ADMITTED row on disk: {rows}"
    assert admitted[0].get("origin") == "client", (
        f"origin did not survive to the file: {admitted[0]}")
    assert admitted[0].get("id_type") == "int", (
        "the field this record already carried must still be there")
