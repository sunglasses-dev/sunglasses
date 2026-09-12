"""
test_pattern_name_hygiene.py — PATTERN NAMES ARE PUBLISHED, SO THEY MUST BE CLEAN.

Every pattern `name` is rendered on sunglasses.dev and shipped inside the wheel.
Sixty-nine of them carried research residue that should never have left the
farm: the date a work order ran, a run id, an internal `.md` filename, and the
account names the Jack hands run under (`azrollinaz`, `qaqu`, `claw`).

"Citation-presence validation laundering — C20260718T133021_azrollinaz"

That is a private build artifact on a public page. Renaming them once fixes the
sixty-nine that exist; this gate is what stops the seventieth, because the names
are written by an automated farm that has no reason to know the convention.

Ids and predicates are untouched by the rename, so detection is unchanged.
"""
import json
import pathlib
import re

import pytest

from sunglasses.patterns import PATTERNS

# T9's v2 expression. v1 matched CVE ids such as CVE-2026-45033 through its date
# clause, so the date shape here must not be preceded by `CVE-` or by a digit.
HYGIENE = re.compile(
    r"(?i)(?<!CVE-)(?<!\d)20\d{2}[-_]\d{2}[-_]\d{2}(?!\d)"
    r"|(?<!AGENTS)(?<!CLAUDE)\.md\b"
    r"|C20\d{6}T\d{6}"
    r"|\b(?:azrollinaz|qaqu|claw)\b"
    r"|(?<![-\w])boss(?!-blocker\b)"
)

# Deliberate keeps, each a product or mechanism term rather than a leak.
ALLOWED = {
    "GLS-AW-116",     # "Boss-Blocker" is an approved product term
    "GLS-AIFP-002",   # AGENTS.md is the mechanism, and is meant to be visible
    "GLS-DFP-091",    # same
}

MAX_NAME = 60

# The 69 ids renamed by WO-P1D. Their names are held to the limit exactly.
RENAMED_IDS = frozenset(json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "tests" / "p1d_renamed_ids.json").read_text()
))


def test_no_pattern_name_leaks_a_build_artifact():
    leaked = [(p["id"], p["name"]) for p in PATTERNS
              if p["id"] not in ALLOWED and HYGIENE.search(p["name"])]
    assert leaked == [], (
        "pattern names carry research residue (dates, run ids, .md filenames, "
        f"farm account names): {leaked[:5]}"
    )


# Measured 2026-09-11: 106 names already exceed MAX_NAME, longest 111. That is
# pre-existing and outside this work order, so it is a RATCHET rather than a rule
# invented here. The count may fall and may not rise; the 69 renamed names are
# all within the limit and are asserted exactly.
LONG_NAME_BASELINE = 106


def test_renamed_names_are_short_enough_to_render():
    renamed_too_long = [(p["id"], len(p["name"])) for p in PATTERNS
                        if p["id"] in RENAMED_IDS and len(p["name"]) > MAX_NAME]
    assert renamed_too_long == [], \
        f"a renamed pattern exceeds {MAX_NAME} chars: {renamed_too_long}"


def test_long_names_only_ever_decrease():
    n = sum(1 for p in PATTERNS if len(p["name"]) > MAX_NAME)
    assert n <= LONG_NAME_BASELINE, (
        f"{n} pattern names exceed {MAX_NAME} chars, baseline {LONG_NAME_BASELINE}. "
        "New names must fit; lower the baseline when you shorten existing ones."
    )


def test_pattern_names_are_unique():
    names = [p["name"] for p in PATTERNS]
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert dupes == [], f"duplicate pattern names are ambiguous on the public pages: {dupes[:5]}"


# ── negative controls: every shape the rename removed must still be caught ────

@pytest.mark.parametrize("leaked", [
    "Citation-presence validation laundering — C20260718T133021_azrollinaz",
    "MCP stdio startup environment-variable injection — C20260725T180137_claw",
    "Case-folding mismatch in Custom MCP environment denylist — C20260723T134055_qaqu",
    "2026-06-30_ansi_sgr_conceal_encoding_smuggling_hardening",
    "Finding lifted from WO-P1B-NOTES.md",
    "Boss review queue bypass",
])
def test_control_each_leaked_shape_is_caught(leaked):
    assert HYGIENE.search(leaked), f"the gate must catch {leaked!r}"


@pytest.mark.parametrize("clean", [
    "Citation Presence Validation Laundering",
    "MCP Stdio Startup Environment Injection",
    "ANSI Concealment Encoding Smuggling",
    "Boss-Blocker Suppression Window Abuse",   # the approved product term
    "AGENTS.md / Agent Instruction File Poisoning",
    "CVE-2026-45033 carrier",                  # v1 matched this; v2 must not
])
def test_control_clean_names_are_not_flagged(clean):
    assert not HYGIENE.search(clean), f"the gate must not flag {clean!r}"


def test_control_a_newly_leaked_name_fails_the_gate():
    """The seventieth. Simulated in-memory, since the point is the farm adds one later."""
    injected = [dict(p) for p in PATTERNS]
    injected[0] = dict(injected[0], name="Some new finding — C20260930T101112_azrollinaz")
    leaked = [(p["id"], p["name"]) for p in injected
              if p["id"] not in ALLOWED and HYGIENE.search(p["name"])]
    assert leaked, "a newly added leaked name must fail this gate"
