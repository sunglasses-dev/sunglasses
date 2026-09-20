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


def _tool(name="read_text_file"):
    return {"name": name, "description": f"the {name} descriptor",
            "inputSchema": {"type": "object"}}


def _capture(*names, sha=SNAPSHOT, pages=None):
    """A capture in the shape `approve` actually reads.

    `tools_by_name` is what the RECORD is built from and what the human saw;
    `pages` is what the pins are derived from. They are separate keys in the
    stored file, which is exactly why the two invariants below are worth
    asserting: nothing in the file format forces them to agree.
    """
    return {"sha256": sha,
            "tools_by_name": {n: {"descriptor_sha256": TOOL_SHA} for n in names},
            "pages": [{"tools": [_tool(n) for n in
                                 (names if pages is None else pages)]}]}


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
    """The capture has to NAME the tool now.

    This used to approve `payload={"tools": []}` and still expect the call
    through, which worked only because `approve` invented a `read_text_file`
    entry whenever the capture had no tools. T505 removed that invention, so an
    empty capture is now a true statement about a server with no tools and the
    call is refused. Naming the tool is what makes the positive half of this
    test mean "approved", instead of meaning "we made one up".
    """
    store.capture(SNAPSHOT, payload=_capture("read_text_file"))
    store.approve(snapshot_sha256=SNAPSHOT, viewed=True)
    _attempt(store)
    assert store.may_call("read_text_file", TOOL_SHA) is None
    assert store.may_call("read_text_file", "e" * 64) == "DESCRIPTOR_CHANGED"
    assert store.may_call("write_file", TOOL_SHA) == "DESCRIPTOR_CHANGED"


def test_a_tool_the_record_never_named_is_never_pinned(store, tmp_path):
    """Invariant 2 of the approving-pins ruling (T9, 09-14 08:34).

    Approving pins the descriptors, and a pin is what makes `check_pin` read
    clean. So a pin written for a tool the approval record does NOT name opens
    the gate for a tool no human ever saw, with a clean receipt attached. The
    two halves of a capture are separate keys and nothing in the format forces
    them to agree, so `_write_pins` has to enforce it.
    """
    store.capture(SNAPSHOT, payload=_capture(
        "read_text_file", pages=["read_text_file", "shadow_tool"]))
    store.approve(snapshot_sha256=SNAPSHOT, viewed=True)
    pinned = json.loads((tmp_path / "pins.json").read_text())["tools"]
    assert any(name.endswith("__read_text_file") for name in pinned)
    assert not any(name.endswith("__shadow_tool") for name in pinned), pinned


def test_pins_come_only_from_the_capture_the_record_names(store, tmp_path):
    """Invariant 1 of the same ruling.

    A second capture on disk is an ordinary thing: every `list_changed` writes
    one. Approving sha A must pin A's descriptors and nothing else, or a
    capture the human declined would be pinned by the approval of one they
    accepted.
    """
    other = "f" * 64
    store.capture(other, payload=_capture("declined_tool", sha=other))
    store.capture(SNAPSHOT, payload=_capture("read_text_file"))
    store.approve(snapshot_sha256=SNAPSHOT, viewed=True)
    pinned = json.loads((tmp_path / "pins.json").read_text())["tools"]
    assert any(name.endswith("__read_text_file") for name in pinned)
    assert not any(name.endswith("__declined_tool") for name in pinned), pinned


def test_a_live_activation_does_not_outlive_the_record_it_was_granted_from(store):
    """A REVOCATION is an edit made without asking us, and this is the only row
    that makes it mean anything.

    The other invalidation rows all reach `_blocked()` first: a corrupt or
    duplicate-keyed record is INVALID before `may_call` compares anything, so
    they pass whatever the comparison below does. This one replaces the record
    with a VALID one naming a different snapshot — the shape a real revocation
    or re-approval takes — so the cached activation is the only thing that could
    still authorise the call.

    Found by `mutate_approvals.py` GATE-REVOKED, which survived every existing
    control: deleting the comparison changed no test result, which is what an
    uncovered refusal looks like from the outside.
    """
    store.capture(SNAPSHOT, payload=_capture("read_text_file"))
    store.approve(snapshot_sha256=SNAPSHOT, viewed=True)
    assert _attempt(store).activated
    assert store.may_call("read_text_file", TOOL_SHA) is None

    # THE EDIT COMES FROM OUTSIDE, which is the whole point and is why
    # `write_raw` is wrong here: writing through the store clears the cached
    # activation, so `_blocked()` answers APPROVAL_REQUIRED and the comparison
    # this row exists for is never reached. A revocation performed by anything
    # else on the machine leaves the activation cached, and then the comparison
    # against what is on disk NOW is the only thing standing between a
    # withdrawn approval and a forwarded call.
    record = json.loads(store._path.read_text())
    record["snapshot_sha256"] = "f" * 64
    store._path.write_text(json.dumps(record))

    assert store.may_call("read_text_file", TOOL_SHA) == "DESCRIPTOR_CHANGED"


def test_a_failed_reactivation_of_a_live_approval_remembers_why(store):
    """T5.R4, the positive half of retirement.

    Clearing the admission alone makes the next call read APPROVAL_REQUIRED,
    which describes a server nobody ever approved and hides that THIS one
    changed underneath an approval that existed. The provenance has to outlive
    the activation, or the state reported is a quieter, wronger one.
    """
    store.capture(SNAPSHOT, payload=_capture("read_text_file"))
    store.approve(snapshot_sha256=SNAPSHOT, viewed=True)
    assert _attempt(store).activated
    assert store.state() == approvals.APPROVED
    again = _attempt(store, server_identity="fs-someone-else")
    assert not again.activated and again.provenance == "DESCRIPTOR_CHANGED"
    assert store.state() == approvals.INVALIDATED
    assert store.may_call("read_text_file", TOOL_SHA) == "DESCRIPTOR_CHANGED"


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
