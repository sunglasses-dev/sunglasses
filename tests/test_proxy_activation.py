"""T5.R3's orchestration, specified before it exists.

The store grades an activation and the collector produces a snapshot, and
nothing has ever run one into the other. This is that step, and it is short
because almost all of it is one ordering decision.

T5.R3(d) says the approval-record revision and the invalidation epoch must
equal the values read AT THE START of this activation attempt. Read them again
at the end and the check is vacuous: it compares the world to itself and passes
every time, including the run where a human revoked the approval while we were
scanning sixty four pages of descriptors. The whole clause exists to make a
completed scan of a world that has since moved unable to admit anything, so the
two numbers are captured before the first page is requested and carried through
untouched.

The second decision is what happens when the snapshot does not match. T5.R2 and
T5.R3 both say captured: the new descriptors are written where a human can look
at them and approve them, because a session that refuses and keeps no record of
what it saw gives its operator nothing to act on and no way out of the refusal.
"""
import pytest

activation = pytest.importorskip(
    "sunglasses.proxy.activation",
    reason="the activation orchestration is the slice being specified")

from sunglasses.proxy import approvals  # noqa: E402

IDENTITY = "s1"   # Store.approve records the store's own server_id


def _tool(name="echo"):
    return {"name": name, "description": "echoes", "inputSchema": {}}


def _pages(*pages):
    seen = []

    def request(cursor):
        seen.append(cursor)
        return pages[len(seen) - 1]

    request.seen = seen
    return request


def _clean(_page):
    # T5.R3(c) counts the helper's pin outcome as part of the page's evidence.
    return {"accepted": True, "status": "complete", "inspection_complete": True,
            "decision": "allow", "findings": [], "check_pin": "clean"}


def _store(tmp_path):
    return approvals.Store(tmp_path, server_id="s1")


def _approved(store, snapshot_result):
    """What `sunglasses proxy approve` does, through the real door.

    `write_without_human` is not used and cannot be: the store refuses it by
    design, which is T5.R1's point that only the approve command writes an
    approval. The capture is already on disk because the activation wrote it.
    """
    store.approve(snapshot_sha256=snapshot_result.sha256, viewed=True)
    return store


# ── the ordering clause ──────────────────────────────────────────────────

def test_the_revision_and_epoch_are_read_before_the_first_page(tmp_path):
    """The clause this module exists for, and it only shows on an APPROVED
    store.

    A human revoking the approval while sixty four pages of descriptors are
    being scanned must not be able to have that scan admit anything. The first
    version of this test ran against an unapproved store, where the attempt is
    refused for a different reason entirely, so a module reading the numbers at
    the end passed it. The world has to be one that WOULD activate, and then
    move.
    """
    store = _store(tmp_path)
    ready = activation.activate(store, list_pages=_pages({"tools": [_tool()]}),
                                scan=_clean, server_identity=IDENTITY)
    _approved(store, ready.snapshot)
    assert activation.activate(store, list_pages=_pages({"tools": [_tool()]}),
                               scan=_clean,
                               server_identity=IDENTITY).activated is True

    moved = {}

    def request(cursor):
        if not moved:
            store.invalidate()          # the world moves mid scan
            moved["yes"] = True
        return {"tools": [_tool()]}

    outcome = activation.activate(store, list_pages=request, scan=_clean,
                                  server_identity=IDENTITY)
    assert outcome.activated is False, (
        "a scan that finished against a world which has since moved activated")


def test_a_matching_snapshot_on_a_still_world_activates(tmp_path):
    """The control for the test above. Without it, a module that never
    activates anything passes every refusal case in this file."""
    store = _store(tmp_path)
    first = activation.activate(store, list_pages=_pages({"tools": [_tool()]}),
                                scan=_clean, server_identity=IDENTITY)
    assert first.activated is False, "nothing is approved yet"

    _approved(store, first.snapshot)
    second = activation.activate(store, list_pages=_pages({"tools": [_tool()]}),
                                 scan=_clean, server_identity=IDENTITY)
    assert second.activated is True
    assert store.may_call("echo", first.snapshot.tools["echo"]) is None


# ── what a refusal leaves behind ─────────────────────────────────────────

def test_an_unapproved_snapshot_is_captured_for_a_human(tmp_path):
    """T5.R2. A refusal with no record of what was seen leaves the operator
    nothing to approve and no way out of the refusal."""
    store = _store(tmp_path)
    outcome = activation.activate(store, list_pages=_pages({"tools": [_tool()]}),
                                  scan=_clean, server_identity=IDENTITY)
    assert outcome.activated is False
    assert list((tmp_path / "captures").glob("*.json")), "nothing was captured"


def test_a_changed_snapshot_says_descriptor_changed_and_captures_the_new_one(tmp_path):
    """T5.R3's sha mismatch. Not APPROVAL_REQUIRED, which would describe a
    server that was never approved and hide that this one changed."""
    store = _store(tmp_path)
    first = activation.activate(store, list_pages=_pages({"tools": [_tool()]}),
                                scan=_clean, server_identity=IDENTITY)
    _approved(store, first.snapshot)

    changed = activation.activate(
        store, list_pages=_pages({"tools": [_tool(), _tool("rm")]}),
        scan=_clean, server_identity=IDENTITY)
    assert changed.activated is False
    assert changed.provenance == "DESCRIPTOR_CHANGED"
    assert len(list((tmp_path / "captures").glob("*.json"))) == 2


def test_an_incomplete_snapshot_never_reaches_the_store(tmp_path):
    """T8.R13. A prefix has no sha to compare, so there is nothing to hand the
    activation, and handing it one built from a truncation is the exact thing
    the collector refuses to produce."""
    store = _store(tmp_path)
    pages = [{"tools": [_tool(f"t{n}")], "nextCursor": f"p{n}"}
             for n in range(200)]
    outcome = activation.activate(store, list_pages=_pages(*pages), scan=_clean,
                                  server_identity=IDENTITY)
    assert outcome.activated is False
    assert outcome.provenance == "APPROVAL_REQUIRED"
    assert outcome.snapshot.sha256 is None
    assert not list((tmp_path / "captures").glob("*.json")), (
        "a truncation was captured, so a human would be shown a document the "
        "server never finished sending")


def test_an_unclean_page_refuses_with_the_scan_provenance(tmp_path):
    """T5.R3(c). The reason is about the SCAN, not about the approval, because
    a server whose descriptors carry an injection is a different problem from
    one nobody has approved yet."""
    store = _store(tmp_path)
    blocked = {"accepted": True, "status": "complete",
               "inspection_complete": True, "decision": "block",
               "findings": [{"rule_id": "GLS-PI-001", "severity": "high",
                             "source": "engine"}]}
    outcome = activation.activate(store, list_pages=_pages({"tools": [_tool()]}),
                                  scan=lambda page: blocked,
                                  server_identity=IDENTITY)
    assert outcome.activated is False
    assert outcome.snapshot.complete is False


def test_a_server_that_is_not_the_approved_one_is_refused(tmp_path):
    """T5.R3(a). The identity is the first term and the cheapest to forget,
    because everything else about a swapped server can look identical."""
    store = _store(tmp_path)
    first = activation.activate(store, list_pages=_pages({"tools": [_tool()]}),
                                scan=_clean, server_identity=IDENTITY)
    _approved(store, first.snapshot)

    outcome = activation.activate(store, list_pages=_pages({"tools": [_tool()]}),
                                  scan=_clean, server_identity="somebody-else")
    assert outcome.activated is False
    assert outcome.provenance == "DESCRIPTOR_CHANGED"


def test_the_page_scans_reach_the_store_exactly_as_the_collector_produced_them():
    """The activation grades the pages under the release lock, so this module
    forwards them and does not summarise. A collector that refuses unclean
    pages already stops most of these, which is precisely why the forwarding
    itself needs its own assertion rather than relying on that."""
    handed = {}

    class _Spy:
        revision = 0
        epoch = 0
        server_id = "s1"

        def capture(self, sha, payload):
            return sha

        def activate(self, **kw):
            handed.update(kw)
            return type("V", (), {"activated": False, "provenance": "X",
                                  "detail": ""})()

    scans = [{"accepted": True, "status": "complete",
              "inspection_complete": True, "decision": "allow",
              "findings": [], "marker": n} for n in range(2)]
    pages = iter(scans)
    activation.activate(_Spy(), list_pages=_pages({"tools": [_tool()], "nextCursor": "p2"},
                                                  {"tools": [_tool("two")]}),
                        scan=lambda page: next(pages), server_identity="s1")
    assert handed["page_scans"] == scans
    assert handed["server_identity"] == "s1"
