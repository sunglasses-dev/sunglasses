"""The moment authority is revoked is now in the evidence, not just its effects.

Every CONSEQUENCE of an invalidation already named its cause: a dropped
notification carries `reason_code`, a settlement becomes DESCRIPTOR_CHANGED, and
the authority accessor returns the reason while stamping the epoch. The
transition itself was silent, which is only visible in the case nobody tests --
revoke while nothing is outstanding, and there are no consequences to carry the
reason, so the stream says nothing at all.

THE ROWS READ THE RECEIPT BACK FROM DISK. An assertion on `session.events`
cannot tell a working change from the failure this repository has already
measured once: `PERMITTED_FIELDS`'s own comment records a SETTLED row written
with `cause_kind` coming back WITHOUT it, because a name missing from the
allowlist is dropped on the way to disk silently and every in-memory assertion
still passes.
"""
import json
import pathlib

import pytest

from sunglasses.proxy import pump, receipts


def _rows(root):
    """Every receipt row actually on disk, in order."""
    files = sorted((pathlib.Path(root) / "receipts").glob("*.jsonl"))
    out = []
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


def _log(tmp_path):
    return receipts.Log(tmp_path, run_id="t-authority", header={})


def test_revoking_authority_is_recorded_when_nothing_is_outstanding(tmp_path):
    """THE ROW THIS CHANGE EXISTS FOR.

    With no request in flight there is no drop and no settlement, so before
    this change the entire session produced no evidence that authority had
    moved at all.
    """
    session = pump.Session(strict=False)
    session.attach_log(_log(tmp_path)) if hasattr(session, "attach_log") else None
    session.accept_invalidation("DESCRIPTOR_CHANGED")

    kinds = [e["kind"] for e in session.events]
    assert "APPROVAL_INVALIDATED" in kinds, (
        f"authority was revoked with nothing outstanding and the session "
        f"recorded {kinds} -- no consequence existed to carry the cause, which "
        f"is exactly the case this row exists for")


def test_the_record_names_the_reason_and_the_epoch(tmp_path):
    session = pump.Session(strict=False)
    session.accept_invalidation("DESCRIPTOR_CHANGED")
    row = next(e for e in session.events if e["kind"] == "APPROVAL_INVALIDATED")
    assert row["reason_code"] == "DESCRIPTOR_CHANGED", row
    assert row["authority_epoch"] >= 1, row


def test_two_invalidations_are_ORDERED_by_the_epoch(tmp_path):
    """The reason alone cannot order two invalidations, and ordering is what an
    auditor reconstructing a session needs."""
    session = pump.Session(strict=False)
    session.accept_invalidation("DESCRIPTOR_CHANGED")
    session.accept_invalidation("DESCRIPTOR_CHANGED")
    epochs = [e["authority_epoch"] for e in session.events
              if e["kind"] == "APPROVAL_INVALIDATED"]
    assert len(epochs) == 2, epochs
    assert epochs[1] > epochs[0], (
        f"two invalidations recorded the same epoch {epochs}, so the evidence "
        f"cannot say which happened first")


def test_the_epoch_SURVIVES_TO_DISK(tmp_path):
    """The assertion the in-memory ones cannot make.

    A field missing from `PERMITTED_FIELDS` reaches `session.events` and is
    dropped by `_clean` on the way to the file. Every row above would still
    pass. This one would not.
    """
    log = _log(tmp_path)
    log.event("APPROVAL_INVALIDATED", reason_code="DESCRIPTOR_CHANGED",
              authority_epoch=7)
    rows = [r for r in _rows(tmp_path) if r.get("kind") == "APPROVAL_INVALIDATED"]
    assert rows, f"no APPROVAL_INVALIDATED row on disk: {_rows(tmp_path)}"
    assert rows[0].get("authority_epoch") == 7, (
        f"the epoch did not survive to the file: {rows[0]}. That is the "
        f"`cause_kind` failure again -- permitted in memory, dropped on disk.")
    assert rows[0].get("reason_code") == "DESCRIPTOR_CHANGED", rows[0]


@pytest.mark.parametrize("bad", [-1, 1.5, "7", True])
def test_a_bad_epoch_RAISES_rather_than_being_trimmed(bad):
    """`_check_value` exists because five fields carried whatever the caller
    passed. A counter that can arrive as a float, a string, a negative or a
    bool would be the sixth -- and `isinstance(True, int)` is True, so `true`
    would otherwise be written as 1.
    """
    with pytest.raises(ValueError):
        receipts._check_value("authority_epoch", bad)


def test_a_good_epoch_is_accepted():
    """The other direction, or the check above passes by refusing everything."""
    assert receipts._check_value("authority_epoch", 0) is None
    assert receipts._check_value("authority_epoch", 42) is None
    assert receipts._check_value("authority_epoch", None) is None
