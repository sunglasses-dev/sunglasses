"""GLS-SD-010-EMB — the assignment the line anchor cannot reach.

`GLS-SD-010` is anchored `(?m)^KEY=`. #170 refused to pair it on `api_response`
and said why, in the patterns file: "inside a JSON string the key sits mid-line
after quotes and escapes, so the anchor cannot match in the very channel the
sibling would exist for ... A shape for embedded content is a NEW rule with its
own fixtures and review." This is that rule, and this is that review.

FIVE PROPERTIES, and the last three are what make the first two mean anything:

  1. every embedded shape FIRES                        (the rule does its job)
  2. every benign twin stays CLEAN                     (it did not become a
                                                        documentation shredder)
  3. the PARENT's behaviour is byte-identical          (nothing widened under
                                                        cover of a new rule)
  4. each guard is proven by a MUTATION that removes   (a green here means the
     it and is watched go red                           assertion can fail)
  5. the added scan cost is a bounded RATIO            (the boundary did not
                                                        buy coverage with a
                                                        pathological scan)

Property 4 is the one the Sep-17 lesson was written for: a control is not proven
by its green, but by having been aimed at the failing artefact and watched go
red. Each control below rebuilds the engine with one specific defect injected
and asserts the defect is detected -- so a fixture that silently stopped
exercising the rule cannot pass this file.
"""
import copy
import json
import pathlib
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sunglasses.engine import SunglassesEngine          # noqa: E402
from sunglasses.patterns import PATTERNS                # noqa: E402
import sd010_embedded_rows as rows                      # noqa: E402

RULE = "GLS-SD-010-EMB"
PARENT = "GLS-SD-010"

# Every channel the rule declares. The parent carries `file` and still misses
# the embedded shapes on it, so this is not a channel fix and the test says so
# by checking `file` alongside the result-direction channels.
# tool_output and web_content joined 2026-09-23 (T9 ruling 5): a JSON secret
# dump in a tool's output or a fetched page is this rule's shape exactly, and
# the channel lint found both missing with nothing saying it was deliberate.
CHANNELS = ["message", "file", "code", "api_response", "log_memory", "agent_input",
            "tool_output", "web_content"]


def _engine_with(patterns):
    """An engine built over exactly `patterns`, the way the constructor takes them."""
    return SunglassesEngine(patterns=patterns)


def _ids(engine, text, channel="file"):
    r = engine.scan(text, channel=channel)
    data = r if isinstance(r, dict) else r.to_dict()
    return data.get("decision"), sorted(f["id"] for f in (data.get("findings") or []))


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


@pytest.fixture(scope="module")
def without_rule():
    return _engine_with([p for p in copy.deepcopy(PATTERNS) if p["id"] != RULE])


# ── 1. the rule fires on every embedded shape, on every channel it declares ──

@pytest.mark.parametrize("shape", sorted(rows.MUST_FIRE))
@pytest.mark.parametrize("channel", CHANNELS)
def test_every_embedded_shape_is_caught(engine, shape, channel):
    """Blocked on every declared channel, and named by THIS rule where only it can.

    The assertion is coverage, not attribution, and WHICH SURFACE IS READ
    decides which of those two you are measuring.

    `result.findings` is the raw list and reports both ids. `result.to_dict()`
    dedupes, and that is the surface a consumer actually sees -- the CLI, the
    API, the SARIF output. Measured on this head for the bare line start:

        channel        .findings                      to_dict()
        file           SD-010, SD-010-EMB             SD-010
        api_response   SD-010-EMB                     SD-010-EMB

    So on `message`, `file` and `code` -- exactly the parent's three declared
    channels -- a consumer is told GLS-SD-010 and never hears this rule's name,
    and on the other three it hears this one. `_ids` reads `to_dict()` on
    purpose, because a test that read the raw list would assert something no
    user can observe.

    That is why the two line-start rows are exempt HERE and proved separately
    below, by removing the parent and watching this rule still block them. A
    draft of this file dropped the exemption after measuring `.findings`
    instead, found it "never taken", and was wrong on the surface that ships.
    """
    decision, ids = _ids(engine, rows.MUST_FIRE[shape], channel)
    assert decision == "block", (
        f"{shape} on {channel}: {decision}, findings {ids}. This shape is the "
        f"reason the rule exists; if it no longer blocks the anchor regressed.")
    if shape not in rows.PARENT_ALSO_COVERS:
        assert RULE in ids, (
            f"{shape} on {channel}: expected {RULE}, got {ids}. The parent "
            f"structurally cannot reach this shape, so if this id is absent "
            f"the block came from somewhere unrelated and the fixture is not "
            f"measuring the gap.")


@pytest.mark.parametrize("shape", sorted(rows.PARENT_ALSO_COVERS))
@pytest.mark.parametrize("channel", CHANNELS)
def test_the_line_start_shapes_are_covered_by_this_rule_too(shape, channel):
    """The anchor was WIDENED, not moved.

    With GLS-SD-010 taken out of the pattern list, this rule still blocks the
    bare line start. A predicate that had swapped the line anchor for a content
    boundary instead of adding to it would go clean here while every test above
    stayed green, because the parent would be covering for it.
    """
    without_parent = _engine_with(
        [p for p in copy.deepcopy(PATTERNS) if p["id"] != PARENT])
    decision, ids = _ids(without_parent, rows.MUST_FIRE[shape], channel)
    assert RULE in ids, (
        f"{shape} on {channel}: with the parent removed this rule reported "
        f"{ids}. The line start is no longer inside the boundary class, so "
        f"the anchor was traded rather than widened.")
    assert decision == "block"


# ── 2. the benign twins stay clean ──────────────────────────────────────────

@pytest.mark.parametrize("shape", sorted(rows.BENIGN))
@pytest.mark.parametrize("channel", CHANNELS)
def test_the_benign_twins_stay_clean(engine, shape, channel):
    _, ids = _ids(engine, rows.BENIGN[shape], channel)
    assert RULE not in ids, (
        f"{shape} on {channel}: {RULE} fired on content that documents a "
        f"variable rather than leaking one. Widening the boundary until the "
        f"corpus passes is how this rule becomes a documentation shredder.")


# ── 3. the parent did not change ────────────────────────────────────────────

@pytest.mark.parametrize("shape", sorted(rows.MUST_FIRE) + sorted(rows.BENIGN))
def test_the_parent_behaves_exactly_as_it_did(engine, without_rule, shape):
    """The no-widening proof, stated as something a machine can check.

    A new rule may ADD its own id. It may not change what GLS-SD-010 reports on
    any byte, or the two would disagree on the channels they share and nothing
    above this file would notice.
    """
    text = (rows.MUST_FIRE | rows.BENIGN)[shape]
    for channel in CHANNELS:
        _, before = _ids(without_rule, text, channel)
        _, after = _ids(engine, text, channel)
        assert (PARENT in before) == (PARENT in after), (
            f"{shape} on {channel}: the parent reported {PARENT in before} "
            f"without the new rule and {PARENT in after} with it.")
        assert [i for i in after if i != RULE] == before, (
            f"{shape} on {channel}: adding {RULE} changed an unrelated "
            f"finding. before={before} after={after}")


# ── 4. the controls: each guard watched go red ──────────────────────────────

def _mutate(**regex_by_id):
    pats = copy.deepcopy(PATTERNS)
    for p in pats:
        if p["id"] in regex_by_id:
            p["regex"] = [regex_by_id[p["id"]]]
    return _engine_with(pats)


def _rule_regex():
    return [p for p in PATTERNS if p["id"] == RULE][0]["regex"][0]


def test_control_removing_the_rule_turns_every_embedded_shape_red(without_rule):
    """THE MUTATION PAIR. Without this rule the embedded shapes go unreported.

    Aimed at the failing artefact and watched go red: if this list were ever to
    come back empty, the fixtures above would be passing on some OTHER rule's
    finding and property 1 would be worth nothing.
    """
    missed = [s for s in rows.MUST_FIRE
              if RULE not in _ids(without_rule, rows.MUST_FIRE[s])[1]]
    assert sorted(missed) == sorted(rows.MUST_FIRE), (
        "removing the rule left some embedded shape still reporting it, which "
        "is impossible; the fixture set is not measuring what it claims.")
    # And the gap is REAL, not merely unreported by this id: the parent does not
    # cover these either. The two line-start rows are the exception by design.
    for shape in sorted(set(rows.MUST_FIRE) - rows.PARENT_ALSO_COVERS):
        _, ids = _ids(without_rule, rows.MUST_FIRE[shape])
        assert not [i for i in ids if i.startswith("GLS-SD-")], (
            f"{shape} is already covered by {ids} without this rule, so it is "
            f"not evidence of the gap. Replace it with a shape that is.")


def test_control_case_folding_the_key_makes_the_kwarg_twin_fire():
    """The `(?-i:...)` scope is load-bearing, proven by removing it.

    The engine compiles every regex with re.IGNORECASE. With the inline scope
    dropped, an indented lowercase `api_key=` in a constructor example is the
    same string as an indented config line, and the twin fires. Measured on the
    77-document corpus 2026-09-21: case-folded 3 docs, case-sensitive 1.
    """
    folded = _rule_regex().replace("(?-i:", "(?:")
    assert folded != _rule_regex(), "the rule no longer carries an inline (?-i:) scope"
    e = _mutate(**{RULE: folded})
    _, ids = _ids(e, rows.BENIGN["lowercase_python_kwarg_indented"])
    assert RULE in ids, (
        "case-folding the key alternation did NOT make the lowercase kwarg "
        "fire, so the twin is not exercising the case scope and this control "
        "proves nothing.")


def test_control_a_bare_space_boundary_makes_the_prose_twin_fire():
    """The other load-bearing choice: a space is never a boundary.

    Adding one to the boundary class is the smallest possible widening, and it
    is enough to block a sentence that merely names a variable.
    """
    widened = _rule_regex().replace(r"[\"'{\[,]", r"[\"'{\[, ]")
    assert widened != _rule_regex(), "the boundary class is not where it was"
    e = _mutate(**{RULE: widened})
    _, ids = _ids(e, rows.BENIGN["prose_a_space_is_not_a_boundary"])
    assert RULE in ids, (
        "admitting a bare space did NOT make the prose twin fire, so that twin "
        "is not guarding the boundary class.")


# ── 5. the cost is a bounded ratio, never a wall clock ──────────────────────
#
# Seconds belong to whatever machine ran them: the 3.9-vs-3.14 measurements in
# test_api_response_siblings.py show main itself failing an absolute budget on a
# tree these rules are not in. So the gate builds the engine WITHOUT this rule
# and WITH it, in the same process and configuration, runs both over the same
# documents, and asserts what THIS rule adds. Both halves pay for the runner.

COST_RATIO = 4.0
REPEAT_BYTES = 24_000

PATHOLOGICAL = {
    # Many boundaries, no key: every candidate start position, nothing to match.
    "boundaries_without_a_key": '{"a":"' * 900,
    # Many keys, no boundary and no assignment: the alternation is entered and
    # abandoned at every offset.
    "keys_without_a_boundary": "PASSWORD " * 900,
    # Keys and boundaries, assignment always just out of reach.
    "almost_an_assignment": '{"PASSWORD" : ' * 700,
    # The shape the rule is for, repeated.
    "real_matches_repeated": '{"cfg":"PASSWORD=x"}' * 700,
}


def _elapsed(engine, text, reps=3):
    best = None
    for _ in range(reps):
        t = time.perf_counter()
        engine.scan(text, channel="file")
        d = time.perf_counter() - t
        best = d if best is None else min(best, d)
    return best


def test_the_boundary_did_not_buy_coverage_with_a_pathological_scan(engine, without_rule):
    rows_out, worst = [], 0.0
    total_with = total_without = 0.0
    for name, seed in PATHOLOGICAL.items():
        text = (seed * ((REPEAT_BYTES // len(seed)) + 1))[:REPEAT_BYTES]
        a = _elapsed(without_rule, text)
        b = _elapsed(engine, text)
        total_without += a
        total_with += b
        ratio = b / a if a else float("inf")
        worst = max(worst, ratio)
        rows_out.append(f"{name:34} without={a*1000:8.2f}ms with={b*1000:8.2f}ms  x{ratio:.2f}")
    overall = total_with / total_without if total_without else float("inf")
    detail = "\n  ".join(rows_out)
    assert overall <= COST_RATIO, (
        f"GLS-SD-010-EMB multiplies the scan by {overall:.2f}x over these "
        f"shapes, above the {COST_RATIO}x gate.\n  {detail}")


# ── 6. the disclosed cost, and the document that licenses the rule ──────────

# The parametrized disclosed-cost test lived here. DISCLOSED_MISSES is empty
# now, so it collected nothing and pytest reported a permanent SKIP -- a check
# that skips itself, which is worse than no check because it reads as coverage.
# `test_nothing_is_disclosed_as_unreported` asserts the emptiness directly, and
# fails if anything is ever declined again.

FP_DOC = (pathlib.Path(__file__).resolve().parent / "fp_real_world_corpus"
          / "sunglasses-dev__env-var-docs-shapes.md")


def test_the_fp_corpus_document_is_an_ACCEPTED_failure_with_a_written_reason(engine):
    """#219's document now BLOCKS, and that is a decision with a reason on it.

    Its header made staying green the licence for this rule. The licence was
    revisited in writing rather than engineered around: every value-driven
    exclusion that would spare this document was defeated by attacker-chosen
    bytes across two review rounds, and a rule carrying one documented false
    positive is worth more than a rule an attacker can silence.

    So this test no longer asserts the document is clean. It asserts the cost
    is BOOKED -- listed on the ratchet, naming this rule, carrying a reason and
    the ruling that put it there. A cost nobody wrote down is one the next
    author deletes by accident.
    """
    assert FP_DOC.exists(), f"{FP_DOC} is gone; the cost cannot be checked"
    decision, ids = _ids(engine, FP_DOC.read_text(errors="ignore"))
    assert RULE in ids and decision == "block", (
        f"the document no longer blocks ({decision}, {ids}). That may be an "
        f"improvement, but it makes the KNOWN_FAILURES entry stale and the "
        f"entry must go with it.")
    known = json.loads((FP_DOC.parent / "KNOWN_FAILURES.json").read_text())
    entry = known.get(FP_DOC.name)
    assert entry, f"{FP_DOC.name} blocks but is NOT on the ratchet"
    assert RULE in entry["patterns"], (
        f"the ratchet entry does not name {RULE}: {entry['patterns']}")
    assert entry.get("reason") and entry.get("ruled_by"), (
        "an accepted false positive needs a written reason and a ruling, not "
        "just a row")


def test_control_any_value_exclusion_reopens_the_attacker_class():
    """The decision this rule now rests on, stated as something that can fail.

    There is no exclusion left to mutate, so the control puts one BACK -- the
    withdrawn prefix list, the first of the three -- and watches the evasion
    rows go quiet. That is the whole argument for the false positive we accept:
    any test applied to the value is a switch the attacker flips by writing the
    tested shape around the secret.

    If someone adds a carve-out here again, this is where it surfaces, with the
    nine inputs that defeated the last three.
    """
    rx = _rule_regex()
    assert "(?!" not in rx, (
        "the rule has grown a negative lookahead again. Value-driven "
        "exclusions were closed as a class on 2026-09-21 after three of them "
        "were defeated by attacker-chosen bytes; re-opening that needs the "
        "nine attack rows measured, not a new token list.")
    reopened = rx + (r"(?![ \t]*[\"']?[ \t]*"
                     r"(?:<|\$\{|your[_-]|x{3,}|example|changeme|redacted))")
    e = _mutate(**{RULE: reopened})
    quiet = [k for k in rows.MUST_FIRE
             if k.startswith("evasion_") and RULE not in _ids(e, rows.MUST_FIRE[k])[1]]
    assert len(quiet) >= 3, (
        f"putting a value exclusion back silenced only {quiet}; the evasion "
        f"rows are not guarding the class decision.")


def test_nothing_is_disclosed_as_unreported():
    """DISCLOSED_MISSES is empty, and that is an assertion rather than a gap.

    The rule does not inspect the value, so there is no shape it declines to
    report. If a future change adds one back, this fails and the author has to
    say what it is and why an attacker cannot write it.
    """
    assert rows.DISCLOSED_MISSES == {}, (
        f"something is being declined again: {sorted(rows.DISCLOSED_MISSES)}. "
        f"Name the shape, and show an attacker cannot produce it.")


def test_control_removing_the_carriage_return_loses_the_cr_delimited_line():
    """The literal CR in the boundary class is load-bearing, proven by removal.

    The class also carries `\\r` as an ESCAPED two-character sequence, which is
    a different thing and is NOT what this guards. Removing only the literal
    one must lose the CR-delimited row while the CRLF row, which rides on the
    `\\n`, keeps working -- otherwise this control is not aimed at the right
    character.
    """
    narrowed = _rule_regex().replace(r"|\r(?:[ \t]|\\t)*", "", 1)
    assert narrowed != _rule_regex(), "the literal CR is no longer in the class"
    e = _mutate(**{RULE: narrowed})
    assert RULE not in _ids(e, rows.MUST_FIRE["cr_only_line_separator"])[1], (
        "removing the literal CR did not lose the CR-delimited line, so that "
        "row is not guarding this character.")
    assert RULE in _ids(e, rows.MUST_FIRE["crlf_line_separator"])[1], (
        "the CRLF row also broke, so this control is measuring the newline "
        "rather than the carriage return.")


def test_control_indentation_only_after_a_newline_loses_the_escaped_tabs():
    """Indentation after EVERY boundary is load-bearing, proven by narrowing it.

    Round 4's reviewer found 24 of 39 authored candidates unreported, and the
    largest family was this: only the newline alternatives allowed indentation,
    and an ESCAPED tab (backslash-t, which is how a serialiser indents inside a
    JSON string) was not treated as indentation anywhere. Putting the class
    back the way it was must lose those rows again.
    """
    narrowed = _rule_regex().replace(r"|[\"'{\[,](?:[ \t]|\\t)*", r"|[\"'{\[,]", 1)
    assert narrowed != _rule_regex(), "the delimiter class no longer carries indentation"
    e = _mutate(**{RULE: narrowed})
    quiet = [k for k in rows.MUST_FIRE
             if ("tab" in k or "indent" in k)
             and RULE not in _ids(e, rows.MUST_FIRE[k])[1]]
    assert len(quiet) >= 4, (
        f"removing indentation from the delimiter class silenced only {quiet}; "
        f"those rows are not guarding it.")


def test_control_a_literal_only_separator_loses_exactly_the_escaped_rows():
    """The escaped separator class is load-bearing, proven by putting `\\s*=` back.

    Round 7's reviewer found `"PASSWORD\\t=..."` inside a JSON string walking
    past while its literal-tab twin blocked. Narrowing the separator to what it
    was must silence EVERY escaped-separator row and NONE of the paired
    controls -- the literal tab, the space and the escaped tab on the value
    side all blocked before the fix, so if one of them goes quiet here this
    control is measuring something other than the separator.
    """
    narrowed = _rule_regex().replace(r"(?:\s|\\[tnrf])*=", r"\s*=", 1)
    assert narrowed != _rule_regex(), "the separator no longer carries the escaped class"
    e = _mutate(**{RULE: narrowed})
    escaped = sorted(k for k in rows.MUST_FIRE
                     if k.startswith("sep_") and not k.startswith("sep_ctl_"))
    controls = sorted(k for k in rows.MUST_FIRE if k.startswith("sep_ctl_"))
    assert len(escaped) == 7 and len(controls) == 3, (escaped, controls)
    still = [k for k in escaped if RULE in _ids(e, rows.MUST_FIRE[k])[1]]
    assert still == [], (
        f"with the literal-only separator these still fire: {still}; "
        f"they are not guarding the escaped class.")
    lost = [k for k in controls if RULE not in _ids(e, rows.MUST_FIRE[k])[1]]
    assert lost == [], (
        f"the literal-only separator lost the paired controls {lost}; "
        f"this control is not aimed at the escaped separator alone.")
