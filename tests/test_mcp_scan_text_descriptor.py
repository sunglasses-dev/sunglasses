"""The scan_text descriptor says what a result means, and what the tool does not do.

MCP cold run, fix 4 (2026-09-27, measured on 0.6.2). An agent reads a tool's
description before it reads any result, and 0.6.2's said the tool "Returns a
decision (allow/block/quarantine)". The engine has a fourth decision,
`allow_redacted`, and every result says whether inspection was complete. The
description said neither. It also said nothing about what the decision DOES,
which is nothing: the tool reports it to the caller, blocks nothing, redacts
nothing, and quotes the text each finding matched. A cold reader took
`isError: false` for "the input is clean".

THE TEXT IS PINNED WORD FOR WORD, and that is deliberate. The proxy approves a
server by the sha of its whole tools/list (`snapshot._snapshot_sha`, over every
descriptor byte), so any change here retires every proxy approval of our own
MCP server with DESCRIPTOR_CHANGED until the operator approves the new sha. An
edit to this text should be a decision, not a drive by.

The control row is not decoration. The first draft of this text said the tool
"redacts nothing", and our own proxy refused our own server for it: GLS-DFP-122
reads a suppression verb on a page that also carries an input schema and the
word "agent" as instruction smuggling. Measured 2026-09-27, PROHIBITED_CONTENT.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sunglasses import mcp, policy                          # noqa: E402
from sunglasses.proxy import route, snapshot                # noqa: E402

EXPECTED = (
    "Scan text for prompt injection, data exfiltration, credential leaks and "
    "other AI agent security threats. Returns findings, a severity, a decision "
    "(allow, block, quarantine or allow_redacted) and inspection_complete. "
    "The decision is reported to the caller and is not enforced. This tool "
    "blocks nothing and returns the matched text of each finding in full, "
    "allow_redacted included. isError false means the scan ran, not that the "
    "input is clean. "
    "Read is_clean and inspection_complete in the result."
)


def _scan_text_descriptor():
    tools = mcp.handle_tools_list({})["tools"]
    (tool,) = [t for t in tools if t["name"] == "scan_text"]
    return tool["description"]


def _result_fields():
    reply = mcp._tool_scan_text({"text": "a sentence that asks for nothing"})
    body = reply["content"][0]["text"].split("\n\n", 1)[1]
    return set(json.loads(body))


def test_the_descriptor_is_the_pinned_text():
    assert _scan_text_descriptor() == EXPECTED


def test_it_names_every_decision_the_engine_can_return():
    # Read, not typed: the severity map is where a decision comes from, and
    # `allow` is the verdict with no finding at all.
    decisions = set(policy.SEVERITY_TO_DECISION.values()) | {"allow"}
    text = _scan_text_descriptor()
    missing = sorted(d for d in decisions
                     if not re.search(rf"\b{re.escape(d)}\b", text))
    assert missing == []


def test_the_fields_it_tells_the_agent_to_read_are_in_the_result():
    text = _scan_text_descriptor()
    fields = _result_fields()
    for name in ("is_clean", "inspection_complete"):
        assert re.search(rf"\b{name}\b", text), name
        assert name in fields, name


def test_it_says_the_decision_is_reported_and_not_enforced():
    text = _scan_text_descriptor()
    assert "reported to the caller and is not enforced" in text
    assert "This tool blocks nothing" in text
    assert "matched text of each finding in full, allow_redacted included" in text
    assert "isError false means the scan ran, not that the input is clean" in text


def test_the_control_our_own_listing_activates_through_the_proxy_scan():
    """The listing is scanned by the same page scan proxy activation runs. A
    description that trips our own tool poisoning rules would be refused by our
    own proxy, and every row above would still pass."""
    page = mcp.handle_tools_list({})
    r = route.Route(session=None, log=None, upstream_write=None,
                    client_write=None)
    found = snapshot.collect(lambda cursor: page, scan=r._scan_page)
    assert (found.complete, found.reason, found.detail) == (True, None, "")
    assert re.fullmatch(r"[0-9a-f]{64}", found.sha256)


# ── Every descriptor, not only this one ─────────────────────────────────────
# The same three word list sat in the LangChain and CrewAI tool descriptions,
# which a model reads exactly as it reads this one. Fixing one surface and
# leaving its siblings is how the class survives, so the check is over the
# package source. patterns.py is rule data, not text a tool shows a model.

import pathlib                                              # noqa: E402

PACKAGE = pathlib.Path(mcp.__file__).resolve().parent
_SEP = r"[\s/,|]+(?:or\s+)?"
_THREE = re.compile(rf"\ballow{_SEP}block{_SEP}quarantine\b")
_FOUR = re.compile(rf"\ballow{_SEP}block{_SEP}quarantine{_SEP}allow_redacted\b")


def _decision_lists():
    """(path:line, complete) for every allow, block, quarantine list in the package."""
    found = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if path.name == "patterns.py":
            continue
        text = path.read_text(encoding="utf-8")
        complete = {m.start() for m in _FOUR.finditer(text)}
        for m in _THREE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            found.append((f"{path.relative_to(PACKAGE.parent)}:{line}",
                          m.start() in complete))
    return found


def test_no_descriptor_names_three_decisions_without_allow_redacted():
    short = [where for where, complete in _decision_lists() if not complete]
    assert short == []


def test_the_control_the_walk_reads_the_package():
    """An empty walk passes the row above. The scan_text list must be found,
    and found complete, or the walk read nothing."""
    lists = dict(_decision_lists())
    assert lists.get("sunglasses/mcp.py:"
                     f"{_line_of('sunglasses/mcp.py', 'or allow_redacted) and')}") is True
    assert _THREE.search("a decision (allow/block/quarantine) and more")
    assert not _FOUR.search("a decision (allow/block/quarantine) and more")


def _line_of(rel, needle):
    text = (PACKAGE.parent / rel).read_text(encoding="utf-8")
    return text.count("\n", 0, text.index(needle)) + 1
