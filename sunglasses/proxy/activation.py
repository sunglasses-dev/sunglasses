"""T5.R3, running the collector into the store.

Written against `tests/test_proxy_activation.py`, committed first.

Short, and almost all of it is one ordering decision.

T5.R3(d) requires the approval-record revision and the invalidation epoch to
equal what the caller read AT THE START of the attempt. Reading them again at
the end makes the check vacuous: it compares the world to itself and passes
every time, including the run where a human revoked the approval while sixty
four pages of descriptors were being scanned. The clause exists so that a
completed scan of a world that has since moved cannot admit anything, so both
numbers are captured before the first page is requested and carried through
untouched.

The other decision is what a refusal leaves behind. Every outcome captures the
snapshot it saw, because a session that refuses and keeps no record gives its
operator nothing to approve and no way out of the refusal. The capture is what
`sunglasses proxy approve` quotes and re-hashes, and it is never re-fetched at
approve time, so what a human looks at is what was on the wire.
"""
from __future__ import annotations

APPROVAL_REQUIRED = "APPROVAL_REQUIRED"

from . import snapshot as _snapshot


class Outcome:
    """Activated or not, with the snapshot that decided it."""

    __slots__ = ("activated", "provenance", "detail", "snapshot")

    def __init__(self, activated, *, provenance=None, detail="", snapshot=None):
        self.activated = activated
        self.provenance = provenance
        self.detail = detail
        self.snapshot = snapshot

    def __repr__(self):
        if self.activated:
            return "<Outcome activated>"
        return f"<Outcome refused {self.provenance}: {self.detail}>"


def activate(store, *, list_pages, scan, server_identity, collect=None):
    """One attempt: read the world, collect, scan, then commit under the lock."""
    # BEFORE the first page. This is the whole ordering clause.
    revision, epoch = store.revision, store.epoch

    collector = collect or _snapshot.collect
    found = collector(list_pages, scan=scan)

    if not found.complete:
        # T8.R13. There is no sha to compare, by construction, so the store is
        # never asked. Capturing a truncation would put a document in front of
        # a human that the server never finished sending.
        return Outcome(False, provenance=found.reason or APPROVAL_REQUIRED,
                       detail=found.detail, snapshot=found)

    # T5.R2. Captured whatever the verdict, so the operator has the thing they
    # would be approving.
    store.capture(found.sha256, found.capture())

    verdict = store.activate(server_identity=server_identity,
                             snapshot_sha256=found.sha256,
                             page_scans=found.page_scans,
                             revision=revision, epoch=epoch)
    if verdict.activated:
        return Outcome(True, snapshot=found)
    return Outcome(False, provenance=verdict.provenance,
                   detail=verdict.detail or "", snapshot=found)
