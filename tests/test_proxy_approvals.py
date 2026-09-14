"""T5: who may approve, what activation requires, and what a change invalidates.

Specified from the rows before the implementation, and from ASTRA's G2-06,
G2-18 and G2-19 fixtures where they exist.

T5.R3's activation invariant is the row that decides this slice. Four conditions,
ALL required, checked AND COMMITTED under the same release lock as call
admission:

  (a) server identity equals the record's
  (b) the complete paged snapshot sha equals the approved S
  (c) every page's scan is accepted, complete, clean, with check_pin clean
  (d) the approval revision and invalidation epoch still equal what was read
      when this activation attempt STARTED

(d) is the one that is easy to leave out and is the reason the row says
"committed under the same lock". An activation scan takes time. If a
`list_changed` arrives, or the approval record changes, while the scan is
running, then the scan COMPLETED SUCCESSFULLY and describes a world that no
longer exists. Letting it activate is a time-of-check-to-time-of-use hole with a
clean receipt attached, which is the worst kind: every field says approved.

So the tests below check each condition alone, and then check the stale case
directly, because three of four passing is the shape a partial implementation
has.
"""
import json

import pytest

approvals = pytest.importorskip(
    "sunglasses.proxy.approvals",
    reason="approvals are the slice being specified here")

SERVER = "fs-abc123"
SNAPSHOT = "a" * 64
TOOL_SHA = "b" * 64


def _record(**over):
    body = {"server_identity": SERVER, "snapshot_sha256": SNAPSHOT,
            "approved_at": "2026-09-14T00:00:00Z", "approved_by": "human",
            "tools": {"read_text_file": {"descriptor_sha256": TOOL_SHA}}}
    body.update(over)
    return body


def _scan(**over):
    page = {"accepted": True, "status": "complete", "inspection_complete": True,
            "decision": "allow", "findings": [], "check_pin": "clean"}
    page.update(over)
    return [page]


def _attempt(store, **over):
    fields = {"server_identity": SERVER, "snapshot_sha256": SNAPSHOT,
              "page_scans": _scan(), "revision": store.revision,
              "epoch": store.epoch}
    fields.update(over)
    return store.activate(**fields)


@pytest.fixture
def store(tmp_path):
    return approvals.Store(tmp_path, server_id=SERVER)


# ── T5.R1: the record, and who may write it ───────────────────────────────

def test_an_approval_is_written_only_by_the_human_approval_path(store):
    """T5.R1: written ONLY by `proxy approve` after the human viewed exactly
    that capture. Nothing in the serving path may create one."""
    with pytest.raises(approvals.NotApprovable):
        store.write_without_human(_record())


def test_approving_requires_the_snapshot_the_human_actually_viewed(store):
    """The sha the human was shown is the sha that gets approved, or the
    approval is of something else."""
    store.capture(SNAPSHOT, payload={"tools": []})
    with pytest.raises(approvals.NotApprovable):
        store.approve(snapshot_sha256="c" * 64, viewed=True)


def test_approving_without_the_human_having_viewed_it_is_refused(store):
    store.capture(SNAPSHOT, payload={"tools": []})
    with pytest.raises(approvals.NotApprovable):
        store.approve(snapshot_sha256=SNAPSHOT, viewed=False)


def test_a_written_record_says_a_human_approved_it(store):
    store.capture(SNAPSHOT, payload={"tools": []})
    store.approve(snapshot_sha256=SNAPSHOT, viewed=True)
    assert store.read()["approved_by"] == "human"


# ── T5.R2: the states ─────────────────────────────────────────────────────

def test_unapproved_withholds_lists_and_refuses_calls(store):
    assert store.state() == approvals.UNAPPROVED
    assert store.may_deliver_list(SNAPSHOT) == "APPROVAL_REQUIRED"
    assert store.may_call("read_text_file", TOOL_SHA) == "APPROVAL_REQUIRED"


def test_approved_delivers_a_list_only_when_the_snapshot_matches(store):
    store.capture(SNAPSHOT, payload={"tools": []})
    store.approve(snapshot_sha256=SNAPSHOT, viewed=True)
    _attempt(store)
    assert store.state() == approvals.APPROVED
    assert store.may_deliver_list(SNAPSHOT) is None
    assert store.may_deliver_list("d" * 64) == "DESCRIPTOR_CHANGED"


def test_an_approved_call_needs_the_tool_and_its_descriptor_sha(store):
    store.capture(SNAPSHOT, payload={"tools": []})
    store.approve(snapshot_sha256=SNAPSHOT, viewed=True)
    _attempt(store)
    assert store.may_call("read_text_file", TOOL_SHA) is None
    assert store.may_call("read_text_file", "e" * 64) == "DESCRIPTOR_CHANGED"
    assert store.may_call("write_file", TOOL_SHA) == "DESCRIPTOR_CHANGED"


# ── T5.R3: all four conditions, each one alone ────────────────────────────

def _approved(store):
    store.capture(SNAPSHOT, payload={"tools": []})
    store.approve(snapshot_sha256=SNAPSHOT, viewed=True)
    return store


def test_activation_succeeds_when_every_condition_holds(store):
    """The baseline, or nothing below distinguishes anything."""
    _approved(store)
    assert _attempt(store).activated is True
    assert store.state() == approvals.APPROVED


def test_condition_a_a_different_server_identity_does_not_activate(store):
    _approved(store)
    outcome = _attempt(store, server_identity="fs-someone-else")
    assert outcome.activated is False
    assert store.state() == approvals.UNAPPROVED


def test_condition_b_a_different_snapshot_does_not_activate(store):
    _approved(store)
    assert _attempt(store, snapshot_sha256="f" * 64).activated is False
    assert store.state() == approvals.UNAPPROVED


@pytest.mark.parametrize("bad,provenance", [
    ({"status": "incomplete", "inspection_complete": False}, "SCAN_EXCEPTION"),
    ({"accepted": False}, "SCAN_EXCEPTION"),
    ({"decision": "review"}, "REVIEW_REQUIRED"),
    ({"findings": [{"rule_id": "GLS-PI-016-API"}], "decision": "block"},
     "PROHIBITED_CONTENT"),
    ({"check_pin": "deny"}, "SCAN_EXCEPTION"),
])
def test_condition_c_a_page_scan_that_is_not_clean_does_not_activate(store, bad,
                                                                     provenance):
    """T5.R3(c) names the provenance for each, and the session stays UNAPPROVED
    with NO calls admitted. A review is not an approval."""
    _approved(store)
    outcome = _attempt(store, page_scans=_scan(**bad))
    assert outcome.activated is False
    assert outcome.provenance == provenance
    assert store.state() == approvals.UNAPPROVED
    assert store.may_call("read_text_file", TOOL_SHA) is not None


def test_condition_c_checks_every_page_not_only_the_first(store):
    """"every page's worker result". A snapshot is paged, and a check that
    stops at the first page approves the rest unread."""
    _approved(store)
    pages = _scan() + _scan(decision="review")
    assert _attempt(store, page_scans=pages).activated is False


def test_condition_d_a_scan_that_completed_after_the_epoch_moved_cannot_activate(store):
    """The time-of-check hole, and the reason the row says committed under the
    same lock.

    The scan succeeded. Every page is clean, the sha matches, the identity
    matches. And while it ran, a `list_changed` arrived, so it describes a world
    that no longer exists. Activating on it produces a clean receipt for an
    approval nobody granted.
    """
    _approved(store)
    started_revision, started_epoch = store.revision, store.epoch
    store.invalidate(reason="DESCRIPTOR_CHANGED")          # arrives mid-scan
    outcome = store.activate(server_identity=SERVER, snapshot_sha256=SNAPSHOT,
                             page_scans=_scan(), revision=started_revision,
                             epoch=started_epoch)
    assert outcome.activated is False
    assert store.state() != approvals.APPROVED


def test_condition_d_also_catches_the_record_changing_mid_scan(store):
    _approved(store)
    started_revision, started_epoch = store.revision, store.epoch
    store.capture("9" * 64, payload={"tools": []})
    store.approve(snapshot_sha256="9" * 64, viewed=True)   # a new approval
    outcome = store.activate(server_identity=SERVER, snapshot_sha256=SNAPSHOT,
                             page_scans=_scan(), revision=started_revision,
                             epoch=started_epoch)
    assert outcome.activated is False


# ── T5.R4: invalidation, and provenance that outlives it ──────────────────

def test_list_changed_invalidates_and_the_reason_is_not_approval_required(store):
    """T5.R4: provenance retained for the session, so it is never
    APPROVAL_REQUIRED afterwards.

    The distinction is what a client is told. APPROVAL_REQUIRED says nobody has
    approved this yet; DESCRIPTOR_CHANGED says it WAS approved and the server
    changed underneath. Reporting the first for the second hides a server that
    moved.
    """
    _approved(store)
    _attempt(store)
    store.invalidate(reason="DESCRIPTOR_CHANGED")
    assert store.may_call("read_text_file", TOOL_SHA) == "DESCRIPTOR_CHANGED"
    assert store.may_deliver_list(SNAPSHOT) == "DESCRIPTOR_CHANGED"


def test_the_provenance_survives_a_later_unrelated_approval_attempt(store):
    _approved(store)
    _attempt(store)
    store.invalidate(reason="DESCRIPTOR_CHANGED")
    _attempt(store)                                        # tries to re-activate
    assert store.may_call("read_text_file", TOOL_SHA) != "APPROVAL_REQUIRED"


# ── T5.R5: an unusable record is a fault, never an allow ──────────────────

@pytest.mark.parametrize("broken", [
    {"approved_by": "the proxy"},
    {"tools": {"read_text_file": {}}},
    {"snapshot_sha256": None},
    {"server_identity": ""},
])
def test_an_invalid_record_holds_with_scan_exception_and_never_allows(store, broken):
    """T5.R5: never allow, never hook-defer."""
    store.write_raw(_record(**broken))
    assert store.state() == approvals.INVALID
    assert store.may_call("read_text_file", TOOL_SHA) == "SCAN_EXCEPTION"


def test_duplicate_tool_names_are_ambiguous_and_hold(store):
    """The row names duplicates explicitly. Two entries for one tool means the
    record cannot say which descriptor was approved."""
    store.write_raw_text(json.dumps(_record()).replace(
        '"read_text_file": {"descriptor_sha256": "' + TOOL_SHA + '"}',
        '"read_text_file": {"descriptor_sha256": "' + TOOL_SHA + '"}, '
        '"read_text_file": {"descriptor_sha256": "' + "c" * 64 + '"}'))
    assert store.state() == approvals.INVALID
    assert store.may_call("read_text_file", TOOL_SHA) == "SCAN_EXCEPTION"


def test_an_unreadable_record_holds_rather_than_falling_back_to_unapproved(store):
    """UNAPPROVED would be a softer, wrong answer: it invites a fresh approval
    over a record we could not read, which may be a record that was tampered
    with."""
    store.write_raw_text("{not json at all")
    assert store.state() == approvals.INVALID
    assert store.may_call("read_text_file", TOOL_SHA) == "SCAN_EXCEPTION"
