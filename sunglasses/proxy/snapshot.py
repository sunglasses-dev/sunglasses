"""T2.R7 and T8.R13, the paged descriptor snapshot the activation compares to.

Written against `tests/test_proxy_snapshot.py`, committed first from the rows.

T5's activation invariant has been built for hours and had nothing to activate:
it takes a snapshot sha and a per-page scan verdict and nothing produced
either, so the approval gate could not open and no tools/call could be
forwarded at all.

One clause decides the shape of this module, and it is T8.R13's last one: NEVER
ACTIVATE A PREFIX. A server that stops paging, loops its cursor, or runs the
list past its deadline has not handed us a short tool list. It has handed us an
unknown one. The approved sha was computed over a COMPLETE snapshot, so a
prefix that happens to hash to something is not a smaller version of that
agreement, it is a different document with a different hash that no human ever
looked at. Truncation is the cheapest way for a server to hide the tool a human
would have refused: make sure the page it lives on never arrives.

So an incomplete snapshot hands back no sha at all. Not a partial one, not the
sha of what did arrive. Refusing to produce the thing a caller would compare is
a stronger guarantee than asking every caller to remember to check a flag.

The verdict on the pages is NOT made here. Each page's scan result is carried
through untouched so the activation grades them under the release lock, where
the revision and the epoch can be checked at the moment of commit. Summarising
them here would move the decision to the one place that cannot see whether the
world changed while we were looking at it.
"""
from __future__ import annotations

import hashlib
import json
import time

# T8.R13, as separate numbers because they bound separate things.
MAX_PAGES = 64
MAX_TOOLS = 512
MAX_BYTES = 4 * 1024 * 1024
DEADLINE_MS = 10_000

REASON_APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
RULE_APPROVAL = "S4"


class Snapshot:
    """A complete tool list and its hashes, or a stated reason there is none."""

    __slots__ = ("complete", "sha256", "tools", "pages", "page_scans",
                 "bytes", "reason", "rule", "detail")

    def __init__(self, *, complete, sha256=None, tools=None, pages=(),
                 page_scans=(), size=0, reason=None, rule=None, detail=""):
        self.complete = complete
        # No sha on an incomplete snapshot. The absence is the guarantee.
        self.sha256 = sha256 if complete else None
        self.tools = dict(tools or {})
        self.pages = list(pages)
        self.page_scans = list(page_scans)
        self.bytes = size
        self.reason = reason
        self.rule = rule
        self.detail = detail

    def capture(self):
        """T5.R1's stored capture. A human approves these bytes and they are
        re-hashed at approve time, never re-fetched.

        `tools_by_name` is the shape `Store.approve` reads, and it is written
        here rather than left for the approve command to derive. The two halves
        were built separately and did not agree: the collector produced a flat
        name to sha map and approve looked for this key, so an approval built
        from a real capture found nothing where its tool list should have been.
        """
        return {"sha256": self.sha256, "tools": dict(self.tools),
                "tools_by_name": {name: {"descriptor_sha256": value}
                                  for name, value in self.tools.items()},
                "pages": list(self.pages), "bytes": self.bytes}

    def __repr__(self):
        if self.complete:
            return f"<Snapshot {len(self.tools)} tools {self.sha256[:12]}>"
        return f"<Snapshot incomplete {self.detail}>"


def collect(request, *, scan, now=None, max_pages=MAX_PAGES,
            max_tools=MAX_TOOLS, max_bytes=MAX_BYTES,
            deadline_ms=DEADLINE_MS):
    """Drive tools/list to a terminal page, bounded, scanning every page.

    `request(cursor)` issues ONE tools/list in the proxy's own id namespace
    (T2.R6) and returns its result. `scan(page)` inspects that page on the
    api_response channel and returns a worker result.
    """
    now = now or (lambda: time.monotonic() * 1000.0)
    started = now()
    pages, scans, tools = [], [], {}
    followed = set()
    cursor = None
    size = 0

    for index in range(max_pages):
        page = request(cursor)
        if not isinstance(page, dict):
            return _incomplete(pages, scans,
                               "the tools/list result is not a result object")
        pages.append(page)

        encoded = json.dumps(page, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
        size += len(encoded)
        if size > max_bytes:
            return _incomplete(pages, scans,
                               f"the snapshot is more bytes than the {max_bytes} cap")

        result = scan(page)
        scans.append(result)
        if not _page_is_clean(result):
            # T5.R3(c) is an AND over every page. A finding on page forty is a
            # finding in the document being approved, and the pages before it
            # are not separately approvable.
            return _incomplete(pages, scans,
                               "an activation scan of a page was not clean")

        for tool in page.get("tools") or []:
            if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                return _incomplete(pages, scans,
                                   "a tool descriptor has no name")
            tools[tool["name"]] = _descriptor_sha(tool)
        if len(tools) > max_tools:
            return _incomplete(pages, scans,
                               f"more tools than the {max_tools} cap")

        # The deadline is checked AFTER each page and covers the whole list.
        # Per page it would be ten minutes for a server that pages sixty four
        # times, which is the same denial of service with paperwork.
        if now() - started > deadline_ms:
            return _incomplete(pages, scans,
                               f"the list ran past its {deadline_ms} ms deadline")

        nxt = page.get("nextCursor")
        if not nxt:
            return Snapshot(complete=True, sha256=_snapshot_sha(pages),
                            tools=tools, pages=pages, page_scans=scans,
                            size=size)
        if nxt in followed:
            # The cheapest infinite list there is, and from the inside it looks
            # exactly like ordinary paging. Every cursor already followed, not
            # merely the previous one: a b a b never repeats consecutively.
            return _incomplete(pages, scans,
                               "the server repeated a cursor it had already given")
        followed.add(nxt)
        cursor = nxt

    # The cap is reached without a terminal page, and the next request is NOT
    # made. A list that does not end is not a big list.
    return _incomplete(pages, scans,
                       f"more pages than the {max_pages} page cap")


def _incomplete(pages, scans, detail):
    return Snapshot(complete=False, pages=pages, page_scans=scans,
                    reason=REASON_APPROVAL_REQUIRED, rule=RULE_APPROVAL,
                    detail=detail)


def _page_is_clean(result):
    """T5.R3(c), the four terms, each checked rather than summarised."""
    if not isinstance(result, dict):
        return False
    return (result.get("accepted") is True
            and result.get("status") == "complete"
            and result.get("inspection_complete") is True
            and result.get("decision") == "allow"
            and not result.get("findings"))


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _descriptor_sha(tool):
    """T5.R2's per-tool hash, over the WHOLE descriptor.

    `description` and `inputSchema` are in it because they are what a model
    reads and what an attacker edits. A hash over the name alone approves the
    one field nobody needs to change.
    """
    return hashlib.sha256(_canonical(tool)).hexdigest()


def _snapshot_sha(pages):
    """The agreement, over every page in the order they arrived.

    Page order is part of it because that is the document the human was shown.
    Hashing a set of tools instead would let a server reorder its list into a
    different presentation with the same approval.
    """
    digest = hashlib.sha256()
    for page in pages:
        digest.update(_canonical(page))
        digest.update(b"\x00")
    return digest.hexdigest()
