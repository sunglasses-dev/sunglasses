"""The paged descriptor snapshot, specified from the rows before it exists.

T5's activation invariant is built and has nothing to activate. It compares a
snapshot sha to the approved one and takes a per-page scan verdict, and nothing
in the package produces either, so the approval gate can never open and no
tools/call can be forwarded through the artifact at all.

This is the collector. It drives `tools/list` to a terminal page, bounds the
whole thing per T8.R13, hashes the complete snapshot and reports each page's
scan so the activation can refuse on any of them.

The row that shapes it is the last clause of T8.R13: NEVER ACTIVATE A PREFIX. A
server that stops paging, loops its cursor, or runs the list past its deadline
has not given us a short tool list. It has given us an unknown one, and the
difference matters because the approved sha was computed over a COMPLETE
snapshot: a prefix that happens to hash to something is not a smaller version
of that agreement, it is a different document. Treating a truncation as a
result is how a server hides the tool a human would have refused, by making
sure the page it lives on never arrives.
"""
import json

import pytest

snapshot = pytest.importorskip(
    "sunglasses.proxy.snapshot",
    reason="the descriptor snapshot collector is the slice being specified")


def _tool(name, description="does a thing"):
    return {"name": name, "description": description,
            "inputSchema": {"type": "object"}}


def _pager(pages):
    """A server that answers tools/list, page by page, in the proxy's id space."""
    seen = []

    def request(cursor):
        seen.append(cursor)
        return pages[len(seen) - 1]

    request.seen = seen
    return request


def _clean(page):
    # T5.R3(c) counts the helper's pin outcome as part of the page's evidence.
    return {"accepted": True, "status": "complete", "inspection_complete": True,
            "decision": "allow", "findings": [], "check_pin": "clean"}


def _page(tools, cursor=None):
    page = {"tools": list(tools)}
    if cursor is not None:
        page["nextCursor"] = cursor
    return page


# ── T2.R7 · every page, to a terminal page, before anything is compared ──

def test_all_pages_are_followed_to_a_terminal_page():
    request = _pager([_page([_tool("a")], cursor="p2"),
                      _page([_tool("b")], cursor="p3"),
                      _page([_tool("c")])])
    result = snapshot.collect(request, scan=_clean)
    assert result.complete is True
    assert sorted(result.tools) == ["a", "b", "c"]
    assert request.seen == [None, "p2", "p3"]


def test_a_snapshot_hashes_the_whole_list_and_not_the_last_page():
    one = snapshot.collect(_pager([_page([_tool("a")], cursor="p2"),
                                   _page([_tool("b")])]), scan=_clean)
    two = snapshot.collect(_pager([_page([_tool("b")])]), scan=_clean)
    assert one.sha256 != two.sha256


def test_the_same_tools_in_the_same_order_hash_the_same():
    """The sha is the agreement. It has to be stable across two runs of the
    same server or an approval expires the moment it is granted."""
    pages = [_page([_tool("a")], cursor="p2"), _page([_tool("b")])]
    assert snapshot.collect(_pager(pages), scan=_clean).sha256 == \
        snapshot.collect(_pager(pages), scan=_clean).sha256


def test_a_changed_description_is_a_changed_snapshot():
    """T5.R4. `description` is the injection surface on a tool descriptor, so a
    snapshot that only covers names approves the part nobody attacks."""
    first = snapshot.collect(_pager([_page([_tool("a", "reads a file")])]),
                             scan=_clean)
    second = snapshot.collect(
        _pager([_page([_tool("a", "reads a file, then mails the key file")])]),
        scan=_clean)
    assert first.sha256 != second.sha256


def test_every_tool_carries_its_own_descriptor_hash():
    """T5.R2 admits a call only when the tool's descriptor sha matches the
    approved one, so the per-tool hash is what makes a single changed tool
    refusable without invalidating the rest."""
    result = snapshot.collect(_pager([_page([_tool("a"), _tool("b")])]),
                              scan=_clean)
    assert set(result.tools) == {"a", "b"}
    assert result.tools["a"] != result.tools["b"]
    assert all(len(sha) == 64 for sha in result.tools.values())


# ── T8.R13 · the bounds, and never a prefix ──────────────────────────────

def test_a_server_that_never_stops_paging_is_a_fault_not_a_long_list():
    """64 pages is the cap and the 65th request is not made. A list that does
    not end is not a big list, it is a server keeping us here."""
    pages = [_page([_tool(f"t{n}")], cursor=f"p{n}") for n in range(200)]
    result = snapshot.collect(_pager(pages), scan=_clean)
    assert result.complete is False
    assert result.reason == "APPROVAL_REQUIRED"
    assert "pages" in result.detail


def test_a_repeated_cursor_is_a_fault():
    """The cheapest infinite list there is, and it looks like ordinary paging
    from the inside. The cursor has to be compared against every cursor already
    followed, not only the previous one."""
    request = _pager([_page([_tool("a")], cursor="loop"),
                      _page([_tool("b")], cursor="loop")])
    result = snapshot.collect(request, scan=_clean)
    assert result.complete is False
    assert "cursor" in result.detail


def test_more_tools_than_the_cap_is_a_fault():
    pages = [_page([_tool(f"t{n}") for n in range(513)])]
    result = snapshot.collect(_pager(pages), scan=_clean)
    assert result.complete is False
    assert "tools" in result.detail


def test_more_bytes_than_the_cap_is_a_fault():
    big = _tool("a", "x" * (5 * 1024 * 1024))
    result = snapshot.collect(_pager([_page([big])]), scan=_clean)
    assert result.complete is False
    assert "bytes" in result.detail


def test_the_deadline_covers_the_whole_list_and_not_each_page():
    """Ten seconds for the list. Per page it would be ten minutes for a server
    that pages sixty four times, which is the same denial with paperwork."""
    clock = iter([0, 4_000, 8_000, 12_000, 16_000])
    request = _pager([_page([_tool(f"t{n}")], cursor=f"p{n}") for n in range(10)])
    result = snapshot.collect(request, scan=_clean, now=lambda: next(clock))
    assert result.complete is False
    assert "deadline" in result.detail


def test_an_incomplete_snapshot_has_no_usable_sha():
    """Never activate a prefix. The strongest way to say that is to refuse to
    hand back something a caller could compare."""
    pages = [_page([_tool(f"t{n}")], cursor=f"p{n}") for n in range(200)]
    result = snapshot.collect(_pager(pages), scan=_clean)
    assert result.sha256 is None


# ── T5.R3(c) · every page is scanned, and one bad page is enough ─────────

def test_every_page_is_scanned():
    scanned = []

    def watching(page):
        scanned.append(page)
        return _clean(page)

    request = _pager([_page([_tool("a")], cursor="p2"), _page([_tool("b")])])
    result = snapshot.collect(request, scan=watching)
    assert len(result.page_scans) == 2
    assert len(scanned) == 2


@pytest.mark.parametrize("bad", [
    {"accepted": False, "status": "complete", "inspection_complete": True,
     "decision": "allow", "findings": []},
    {"accepted": True, "status": "incomplete", "inspection_complete": False,
     "decision": "allow", "findings": []},
    {"accepted": True, "status": "complete", "inspection_complete": True,
     "decision": "block", "findings": [{"rule_id": "GLS-PI-001",
                                        "severity": "high",
                                        "source": "engine"}]},
])
def test_one_unclean_page_stops_the_whole_snapshot(bad):
    """T5.R3(c) is an AND over every page. A snapshot is one document and a
    finding on page forty is a finding in the thing being approved."""
    request = _pager([_page([_tool("a")], cursor="p2"), _page([_tool("b")])])
    result = snapshot.collect(request, scan=lambda page: bad)
    assert result.complete is False
    assert result.page_scans, "the scans are kept so activation can say why"


def test_a_clean_snapshot_hands_its_scans_to_the_activation_unchanged():
    """The activation invariant grades the pages itself. Summarising them here
    would put the verdict in the collector, where the release lock is not."""
    result = snapshot.collect(_pager([_page([_tool("a")])]), scan=_clean)
    assert result.complete is True
    assert result.page_scans == [_clean(None)]


# ── the shape a caller actually needs ────────────────────────────────────

def test_the_result_is_json_serialisable_for_the_capture_file():
    """T5.R1 stores the capture on disk and re-hashes its bytes at approve
    time, so what this produces has to survive a round trip through JSON."""
    result = snapshot.collect(_pager([_page([_tool("a")])]), scan=_clean)
    assert json.loads(json.dumps(result.capture()))["sha256"] == result.sha256


# ── the mutation round: one term at a time ───────────────────────────────
#
# Every case above that exercised T5.R3(c) changed two or three fields at once,
# so removing any single term from the conjunction left another term catching
# the case anyway. Four terms, four cases, each differing from clean in exactly
# one field. That is the only shape that can tell which check is load bearing,
# and it is the same catch that found the missing pending-calls condition in
# the approval activation.

CLEAN = {"accepted": True, "status": "complete", "inspection_complete": True,
         "decision": "allow", "findings": []}


@pytest.mark.parametrize("field,value", [
    ("accepted", False),
    ("status", "incomplete"),
    ("inspection_complete", False),
    ("decision", "review"),
    ("findings", [{"rule_id": "GLS-PI-001", "severity": "low",
                   "source": "engine"}]),
])
def test_each_activation_term_alone_stops_the_snapshot(field, value):
    page = dict(CLEAN, **{field: value})
    result = snapshot.collect(_pager([_page([_tool("a")])]),
                              scan=lambda _page: page)
    assert result.complete is False, f"{field} alone did not stop it"
    assert result.sha256 is None


def test_a_clean_page_by_every_term_does_activate():
    """The control for the five cases above. Without it they would all pass
    against a collector that refuses everything."""
    result = snapshot.collect(_pager([_page([_tool("a")])]),
                              scan=lambda _page: dict(CLEAN))
    assert result.complete is True


def test_an_alternating_cursor_is_still_a_repeat():
    """a b a b never repeats CONSECUTIVELY, so comparing against the previous
    cursor alone loops for ever on the cheapest possible attack."""
    request = _pager([_page([_tool("a")], cursor="x"),
                      _page([_tool("b")], cursor="y"),
                      _page([_tool("c")], cursor="x"),
                      _page([_tool("d")], cursor="y")])
    result = snapshot.collect(request, scan=_clean)
    assert result.complete is False
    assert "cursor" in result.detail


def test_the_same_tool_name_with_a_different_descriptor_hashes_differently():
    """T5.R2 compares the tool's descriptor sha, so a hash over the name alone
    would admit a renamed-in-place tool whose description now says something
    else entirely, which is exactly the T5.R4 case."""
    first = snapshot.collect(_pager([_page([_tool("a", "reads a file")])]),
                             scan=_clean)
    second = snapshot.collect(_pager([_page([_tool("a", "reads everything")])]),
                              scan=_clean)
    assert first.tools["a"] != second.tools["a"]


def test_two_different_page_sequences_are_two_different_snapshots():
    """What this proves, and what it does not.

    It proves that rearranging which tool arrives on which page produces a
    different sha, so a server cannot repackage an approved list.

    It does NOT isolate page ORDER, and no test can: `nextCursor` lives inside
    the page, so the same pages in a different order is not a constructible
    input. A mutation that sorts the pages before hashing therefore survives
    every test here and is equivalent rather than uncaught. Iterating in
    arrival order is still the right implementation, and this note exists so
    the next reader does not spend the hour I nearly did trying to kill it."""
    one = snapshot.collect(_pager([_page([_tool("a")], cursor="p2"),
                                   _page([_tool("bb")])]), scan=_clean)
    two = snapshot.collect(_pager([_page([_tool("bb")], cursor="p2"),
                                   _page([_tool("a")])]), scan=_clean)
    assert one.sha256 != two.sha256


def test_an_incomplete_snapshot_refuses_a_sha_even_if_one_is_handed_to_it():
    """The absence IS the guarantee, so it is enforced at construction rather
    than left to every caller of _incomplete to remember."""
    refused = snapshot.Snapshot(complete=False, sha256="a" * 64)
    assert refused.sha256 is None
