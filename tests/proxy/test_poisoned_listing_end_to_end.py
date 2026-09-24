"""A poisoned tool DESCRIPTION, stopped on the real proxy path or not at all.

The `-API` siblings were measured against the ENGINE: a constructed description
scanned on `api_response`. That answers "would the rule fire", and it is not
the same question as "does the proxy stop it". A `tools/list` RESULT crosses
framing, the selector, the route and the worker before a client sees it, and a
rule that fires in a unit test and never runs on that path is coverage that
does not exist.

So this drives the REAL binary over a pty, against a REAL hostile server
process whose LISTING carries the trigger, and reads the answer off the wire.
`--inject` already made a hostile tools/call RESULT; the listing had no hostile
fixture at all, which is why nothing had asked this before.

RED-FIRST, and the control is the point: the same harness with a BENIGN
description must come back with a result. Without that row, "blocked" is
satisfied by a proxy that blocks everything.
"""
import json
import os
import subprocess
import sys

import pytest

TREE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, TREE)

from test_wrapped_route_end_to_end import INIT, LIST, Wrapped, _refusal  # noqa: E402

sys.path.insert(0, os.path.join(TREE, "tests", "proxy"))

# One trigger per sibling, rendered from the rule's own predicate so the
# stimulus is the shape the rule was written for rather than one I invented.
def _triggers():
    """One trigger per sibling, rendered from the rule's OWN predicate.

    Returns [] rather than skipping: a module-level skip would take the CONTROL
    with it, and a control that does not run is the one thing this file cannot
    afford to lose.
    """
    sys.path.insert(0, os.path.join(TREE, "tests"))
    import re as _re
    try:
        import regex_sample
    except ImportError:
        return []
    from sunglasses.patterns import PATTERNS
    out = []
    for p in PATTERNS:
        if not p["id"].endswith("-API"):
            continue
        # NO FAMILY FILTER. An earlier version listed the three families this
        # branch happened to add, which meant the whole file -- CONTROL
        # INCLUDED -- skipped itself anywhere those families were absent. A
        # check that names the branch it was written on is not a check.
        for rx in p.get("regex") or []:
            s = regex_sample.sample(rx)
            if s and len(s.strip()) >= 8 and _re.search(rx, s, _re.IGNORECASE):
                out.append((p["id"], s.strip()))
                break
    return out


TRIGGERS = _triggers()


class PoisonedListing(Wrapped):
    """A Wrapped server whose LISTING carries the trigger from the start."""

    def __init__(self, tmp_path, trigger):
        self.work = tmp_path
        self.home = tmp_path / "home"
        self.home.mkdir(exist_ok=True)
        self.cfg = tmp_path / ".mcp.json"
        self.cfg.write_text(json.dumps({"mcpServers": {"echo": {
            "command": "python3",
            "args": ["-m", "sunglasses.proxy.echo_server",
                     "--poison-description", trigger]}}}))
        self.env = dict(os.environ, PYTHONPATH=TREE,
                        PYTHONDONTWRITEBYTECODE="1",
                        HOME=str(self.home), SUNGLASSES_HOME=str(self.home))
        r = subprocess.run([sys.executable, "-m", "sunglasses", "install", "echo",
                            "--config", str(self.cfg)],
                           capture_output=True, text=True, env=self.env,
                           cwd=self.work)
        assert r.returncode == 0, r.stdout + r.stderr
        self.entry = json.loads(self.cfg.read_text())["mcpServers"]["echo"]


def test_the_fixture_can_actually_poison_a_listing(tmp_path):
    """THE CONTROL. A benign listing must come back as a RESULT.

    If this fails, every blocked row below is satisfied by a proxy that refuses
    everything, and none of them is evidence about descriptions.
    """
    clean = Wrapped(tmp_path)
    data = _refusal(clean.talk([INIT, LIST]), 2)
    assert clean.approve_at_a_terminal(
        data["server_id"], data["snapshot_sha256"]) == 0
    frames = clean.talk([INIT, LIST])
    answer = next(f for f in frames if f.get("id") == 2)
    assert "result" in answer, (
        "a BENIGN listing was not returned, so this harness cannot tell a "
        "block from a refusal and nothing below means anything")


@pytest.mark.parametrize("rule_id,trigger",
                         TRIGGERS or [pytest.param("none", "", marks=pytest.mark.skip)],
                         ids=lambda v: v if isinstance(v, str) and v.startswith("GLS") else "")
def test_a_poisoned_description_is_stopped_on_the_wire(tmp_path, rule_id, trigger):
    """The listing carries the trigger; the client must not receive it."""
    # THE POISON GOES IN BEFORE THE FIRST INSTALL. An earlier version built a
    # clean server, rewrote the config and installed AGAIN -- the second
    # install exits 2 ("already installed"), so all fourteen rows failed on a
    # harness error and not one of them ever reached the proxy. A fail row is a
    # harness defect until the stimulus is proven, and that was fourteen of
    # them.
    hostile = PoisonedListing(tmp_path, trigger)

    # NO APPROVAL STEP, and that is the finding rather than an omission. A
    # CLEAN listing comes back APPROVAL_REQUIRED and carries a `server_id` to
    # approve. A POISONED one never gets that far: it is refused on CONTENT
    # first, so there is no server_id to hand to a terminal. An earlier version
    # of this row approved first, hit KeyError on every trigger, and looked
    # like fourteen product failures.
    answer = next(f for f in hostile.talk([INIT, LIST]) if f.get("id") == 2)
    assert "result" not in answer, (
        f"{rule_id}: the poisoned description reached the client")
    blocked = answer["error"]["data"]
    assert blocked["reason_code"] == "PROHIBITED_CONTENT", (
        f"{rule_id}: refused as {blocked['reason_code']}. APPROVAL_REQUIRED "
        f"would mean 'never looked' -- the control row shows a CLEAN listing "
        f"gets exactly that, so this must be the other one.")


def test_a_tools_list_block_names_the_rule_that_refused_it(tmp_path):
    """The audit gap, CLOSED, and this is the test that used to assert it open.

    Until 2026-09-22 a poisoned listing came back `PROHIBITED_CONTENT` with
    `rule_ids: []` and `inspected_utf8_bytes: 0`, while the tools/call refusal
    for a credential NAMED its rules. An operator asking why a server's listing
    was refused got a reason code and nothing else.

    WHICH PATH REFUSED IT was the whole question. Not the result-scan path: the
    SNAPSHOT COLLECTOR stops a poisoned listing before the approval store is
    ever asked for a verdict, and that return dropped the ids it was holding.
    They were never missing -- `found.page_scans` had them all along. That is
    also why `inspected_utf8_bytes` reads 0: those bytes belong to the
    result-scan envelope, and this refusal does not come from there.

    The ids named are the ones on the FIRST page that carried findings, not a
    union over every page: an operator needs to know which tool's description
    was prohibited, and merging them would name rules from pages that were
    clean.
    """
    if not TRIGGERS:
        pytest.skip("no rendered triggers on this branch")
    rule_id, trigger = TRIGGERS[0]
    hostile = PoisonedListing(tmp_path, trigger)
    data = next(f for f in hostile.talk([INIT, LIST])
                if f.get("id") == 2)["error"]["data"]
    assert data["reason_code"] == "PROHIBITED_CONTENT"
    assert data["rule_ids"], (
        "the listing refusal names no rule again -- a block that names no rule "
        "cannot be audited, which is the sentence this whole row exists for")
    assert rule_id in data["rule_ids"], (
        f"the refusal names {data['rule_ids']} but the listing was poisoned "
        f"with {rule_id}'s own trigger")


def test_a_zero_byte_count_is_qualified_by_inspection_complete(tmp_path):
    """The zero is not bare: the envelope says in the same breath why it is 0.

    THE REVIEW OBJECTION THIS ANSWERS, and it was a fair one to raise. A
    refusal that names its rules while reporting `inspected_utf8_bytes: 0`
    reads, on its own, like a measurement that came back empty -- and the
    proposed fix was to OMIT the counter when nothing was measured.

    Omitting it would have been the wrong repair and this test is the right
    one. `envelope.withheld` emits `inspection_complete` on the line directly
    above the counter, so the envelope already distinguishes "inspected
    nothing" from "inspected and found nothing"; the counter is a required
    parameter of a deliberately fixed key set, and the ONLY conditional pair in
    that envelope carries a comment saying no other refusal should grow a field
    it has no use for. So the meaning of the zero is pinned HERE, as a control,
    rather than by deleting the number that needed explaining.

    A future change that reports a non-zero count on a path that never
    inspected anything, or that drops `inspection_complete`, fails this row.
    """
    if not TRIGGERS:
        pytest.skip("no rendered triggers on this branch")
    rule_id, trigger = TRIGGERS[0]
    hostile = PoisonedListing(tmp_path, trigger)
    data = next(f for f in hostile.talk([INIT, LIST])
                if f.get("id") == 2)["error"]["data"]

    assert data["reason_code"] == "PROHIBITED_CONTENT"
    assert data["inspection_complete"] is False, (
        "the refusal claims a COMPLETED inspection, so a zero byte count below "
        "would be a measurement of nothing rather than an absence of one")
    for counter in ("inspected_utf8_bytes", "observed_content_bytes",
                    "elapsed_ms"):
        assert counter in data, (
            f"{counter} is absent; the envelope is a fixed key set and a "
            f"consumer that reads it positionally cannot tell a dropped field "
            f"from a dropped measurement")
        assert data[counter] == 0, (
            f"{counter} is {data[counter]!r} on a refusal that reports "
            f"inspection_complete false -- a count from an inspection that "
            f"never ran is worse than no count")
