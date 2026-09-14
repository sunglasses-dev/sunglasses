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

IDENTITY = "server-identity-sha"


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
    return {"accepted": True, "status": "complete", "inspection_complete": True,
            "decision": "allow", "findings": []}


def _store(tmp_path):
    return approvals.Store(tmp_path, server_id="s1")


def _approved(tmp_path, store, sha, tools):
    """What `sunglasses proxy approve` does: a human viewed exactly this sha."""
    store.capture(sha, {"tools": tools})
    store.write_without_human({
        "server_identity": IDENTITY, "snapshot_sha256": sha,
        "approved_at": "now", "approved_by": "human",
        "tools": {name: {"descriptor_sha256": value}
                  for name, value in tools.items()}})
    return store


# ── the ordering clause ──────────────────────────────────────────────────

def test_the_revision_and_epoch_are_read_before_the_first_page(tmp_path):
    """The clause this module exists for. A human revoking the approval while
    sixty four pages are being scanned must not be able to have the scan admit
    anything, and reading the numbers at the end compares the world to itself."""
    store = _store(tmp_path)
    moved = {}

    def request(cursor):
        # the world moves in the middle of the scan
        if not moved:
            store.invalidate()
            moved["yes"] = True
        return {"tools": [_tool()]}

    outcome = activation.activate(store, list_pages=request, scan=_clean,
                                  server_identity=IDENTITY)
    assert outcome.activated is False


def test_a_matching_snapshot_on_a_still_world_activates(tmp_path):
    """The control for the test above. Without it, a module that never
    activates anything passes every refusal case in this file."""
    store = _store(tmp_path)
    first = activation.activate(store, list_pages=_pages({"tools": [_tool()]}),
                                scan=_clean, server_identity=IDENTITY)
    assert first.activated is False, "nothing is approved yet"

    _approved(tmp_path, store, first.snapshot.sha256,
              first.snapshot.tools)
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
    _approved(tmp_path, store, first.snapshot.sha256, first.snapshot.tools)

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
    _approved(tmp_path, store, first.snapshot.sha256, first.snapshot.tools)

    outcome = activation.activate(store, list_pages=_pages({"tools": [_tool()]}),
                                  scan=_clean, server_identity="somebody-else")
    assert outcome.activated is False
    assert outcome.provenance == "DESCRIPTOR_CHANGED"
