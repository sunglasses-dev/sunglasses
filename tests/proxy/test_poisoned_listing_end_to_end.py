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
        parent = p["id"][:-4]
        if not any(parent.startswith(x) for x in ("GLS-TP-", "GLS-TMS-", "GLS-MTI-")):
            continue
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


def test_a_tools_list_block_names_no_rule_and_a_tools_call_block_does(tmp_path):
    """THE AUDIT GAP, pinned so it cannot drift while nobody is looking.

    A poisoned listing IS stopped on the wire -- every row above proves that.
    But its refusal comes back with `rule_ids: []` and
    `inspected_utf8_bytes: 0`, while the tools/call refusal for a credential
    names its rules (test_wrapped_route_end_to_end asserts exactly that, and
    passes). Same channel, same proxy, two different answers about what was
    inspected.

    So an operator asked "why was this server's listing refused?" gets
    PROHIBITED_CONTENT and nothing else. A block that names no rule cannot be
    audited -- the credential test says so in its own words, and this surface
    does not meet it.

    This asserts the CURRENT behaviour deliberately. It is a defect to fix,
    not a property to keep, and when it is fixed this test fails and is
    rewritten -- which is the point of pinning it rather than leaving it as a
    sentence in a report.
    """
    if not TRIGGERS:
        pytest.skip("no rendered triggers on this branch")
    hostile = PoisonedListing(tmp_path, TRIGGERS[0][1])
    data = next(f for f in hostile.talk([INIT, LIST])
                if f.get("id") == 2)["error"]["data"]
    assert data["reason_code"] == "PROHIBITED_CONTENT"
    assert data["rule_ids"] == [], (
        "the listing refusal now NAMES a rule -- the audit gap is closed, so "
        "delete this test and tighten the rows above to assert rule_ids")
    assert data["inspected_utf8_bytes"] == 0, (
        "the listing refusal now reports inspected bytes -- same as above")
