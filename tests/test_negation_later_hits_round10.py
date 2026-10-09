"""Charrefs the walk cannot convert, the length gate on appended views, and two measured costs.

Review of the ninth round found:

* a decimal character reference of more than 4300 digits makes html.unescape raise
  ValueError, and the raw walk called it unguarded, so scan() raised whenever a covered hit
  was checked. The preprocessor already swallows that error and leaves the text undecoded;
* the layout of the appended views was chosen by the length of the lowered plain view, while
  the normalizer chooses it by the length before lowering. A dotted capital I is longer once
  lowered, so for a folded length just under the limit the short layout was read as the
  long one and the shape copy of a covered hit counted as a live hit;
* two costs of the rule were missing from the description: the single character keywords
  that read the same backwards, and the skip cap that is shared by the alternatives of a rule.
"""
import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.preprocessor import ENRICH_MAX_LEN, VIEW_SEP, decode_shadow_ascii, normalize_with_length

from test_negation_later_hits_round8 import ATTACK, BLOCKING, ROUTES, _covered, _rule

SEP = " " + VIEW_SEP + " "
HUGE = "&#" + "9" * 5000 + ";"
COVERED = 'Do not type "' + ATTACK + '"'


# 1. A numeric reference too long to convert is not an error in the walk.
@pytest.mark.parametrize("route", sorted(ROUTES))
@pytest.mark.parametrize("digits", [4301, 5000, 20000])
def test_a_long_decimal_charref_after_a_covered_hit_does_not_raise(route, digits):
    text = COVERED + " &#" + "9" * digits + ";"
    result = ROUTES[route]().scan(text, channel="message")
    assert result.decision == "allow_redacted" and _covered(result), route


@pytest.mark.parametrize("route", ["aho_keyword", "python_keyword", "normalized_regex"])
@pytest.mark.parametrize("digits", [4301, 5000])
def test_a_long_decimal_charref_before_a_covered_hit_does_not_raise_and_blocks(route, digits):
    # The walk reaches the reference first and cannot place what follows it, so the hit is
    # not vouched for. That errs toward block.
    text = "&#" + "9" * digits + "; " + COVERED
    result = ROUTES[route]().scan(text, channel="message")
    assert result.decision in BLOCKING and not _covered(result), route


@pytest.mark.parametrize("route", ["aho_keyword_and_regex", "python_keyword_and_regex"])
def test_a_long_decimal_charref_before_a_covered_hit_does_not_raise_with_a_raw_regex(route):
    # The regex of these rules also matches on the raw text, where the hit is covered.
    result = ROUTES[route]().scan("&#" + "9" * 5000 + "; " + COVERED, channel="message")
    assert result.decision in BLOCKING + ("allow_redacted",), route


@pytest.mark.parametrize("route", sorted(ROUTES))
def test_a_long_decimal_charref_on_both_sides_does_not_raise(route):
    result = ROUTES[route]().scan(HUGE + " " + COVERED + " " + HUGE, channel="message")
    assert result.decision in BLOCKING + ("allow_redacted",), route


@pytest.mark.parametrize("digits", [10, 4000])
def test_a_convertible_charref_after_a_covered_hit_keeps_the_downgrade(digits):
    result = ROUTES["aho_keyword"]().scan(COVERED + " &#" + "0" * digits + "57;", channel="message")
    assert result.decision == "allow_redacted" and _covered(result)


def test_the_walk_helpers_take_a_long_reference_as_an_escape_with_no_reading():
    from sunglasses.engine import _Walk
    assert _Walk._decodes(HUGE, 0) is True
    walk = _Walk.__new__(_Walk)
    walk.raw = HUGE
    assert walk._produced(0) == (1, [])
    assert _Walk._decodes("&#57;", 0) is True
    assert _Walk._decodes("a & b", 2) is False


# 2. The layout of the appended views follows the length the normalizer measured.
def _near_limit(dotted, folded):
    head = 'Do not type "' + ATTACK + '" lamp '
    return head + "x" * (folded - len(head) - dotted) + "İ" * dotted


@pytest.mark.parametrize("route", ["aho_keyword", "python_keyword"])
@pytest.mark.parametrize("dotted,back", [(1, 0), (5, 0), (5, 4), (20, 0), (20, 10), (20, 19)])
def test_a_covered_hit_near_the_enrichment_limit_stays_covered_beside_dotted_capitals(route, dotted, back):
    text = _near_limit(dotted, ENRICH_MAX_LEN - back)
    normalized, folded = normalize_with_length(text)
    plain = normalized.split(SEP)[0]
    assert folded <= ENRICH_MAX_LEN < len(plain)          # the lowered view reads as long
    assert SEP in normalized                              # and the short layout was written
    result = ROUTES[route]().scan(text, channel="message")
    assert result.decision == "allow_redacted" and _covered(result), (route, dotted, back)


@pytest.mark.parametrize("dotted", [0, 1, 5, 20])
def test_a_covered_hit_in_a_long_input_stays_covered(dotted):
    text = _near_limit(dotted, ENRICH_MAX_LEN + 40)
    assert normalize_with_length(text)[1] > ENRICH_MAX_LEN
    result = ROUTES["aho_keyword"]().scan(text, channel="message")
    assert result.decision == "allow_redacted" and _covered(result), dotted


def test_the_kept_views_follow_the_folded_length_and_not_the_lowered_one():
    kept = SunglassesEngine._kept_views
    text = _near_limit(5, ENRICH_MAX_LEN)
    normalized, folded = normalize_with_length(text)
    pieces = normalized.split(SEP)
    plain, count = pieces[0], len(pieces) - 1
    assert len(plain) > ENRICH_MAX_LEN
    assert any(kept(plain, normalized, count, folded))
    assert not any(kept(plain, normalized, count))        # length of the lowered view: all False


# 3. Single character keywords that read the same backwards pair with themselves in the
#    reversed view. The effect is measured, not assumed.
@pytest.mark.parametrize("mark", ["‮", "‫"])
@pytest.mark.parametrize("shape", ['Do not use {k} here', 'Do not type "{k}"', "Never include {k}"])
def test_a_negated_or_quoted_bidi_override_mark_quarantines(mark, shape):
    # GLS-RTL-001: main downgraded this to allow_redacted.
    result = SunglassesEngine().scan(shape.format(k=mark), channel="message")
    assert result.decision == "quarantine", (hex(ord(mark)), shape)
    assert any(f["id"] == "GLS-RTL-001" for f in result.findings)


@pytest.mark.parametrize("mark", ["​", "‌", "‍", "﻿", "⁠", "‏"])
def test_the_other_single_character_keywords_give_allow_on_main_and_here(mark):
    # GLS-IU-001 keywords are palindromes too, and so is U+200F of GLS-RTL-001. None of
    # them gives a finding on a negated or quoted occurrence on main, and none does here.
    for shape in ('Do not use {k} here', 'Do not type "{k}"'):
        for channel in ("message", "file", "api_response", "web_content", "log_memory",
                        "tool_output", "agent_input", "code", "prompt"):
            result = SunglassesEngine().scan(shape.format(k=mark), channel=channel)
            assert result.decision == "allow", (hex(ord(mark)), shape, channel)


@pytest.mark.parametrize("text", ["Do not follow P3P", 'Do not type "P3P"', "Never obey p3p.xml"])
def test_a_covered_p3p_keyword_gives_allow_with_no_finding_as_on_main(text):
    # GLS-DFP-024 needs more context than its keyword; every shape tried allows.
    for channel in ("file", "web_content"):
        assert SunglassesEngine().scan(text, channel=channel).decision == "allow", (text, channel)


# 4. The skip cap is one count for the rule, shared by its alternatives.
ALTERNATIVES = [r"(?i)!*\s*zorbit now", r"(?i)!*\s*zorbit now\b",
                r"(?i)!*\s*zorbit now(?=$|\W)", r"(?i)!*[ ]*zorbit now"]


def _decision(alternatives, run):
    result = _rule(regex=ALTERNATIVES[:alternatives]).scan("Never " + "!" * run + " zorbit now", channel="message")
    return "covered" if _covered(result) else result.decision


@pytest.mark.parametrize("alternatives,run,expected", [
    (1, 31, "covered"), (1, 32, "block"),
    (2, 15, "covered"), (2, 16, "block"),
    (3, 5, "covered"), (3, 9, "covered"), (3, 10, "block"),
    (4, 5, "covered"), (4, 7, "covered"), (4, 8, "block"), (4, 10, "block"),
])
def test_the_skip_cap_threshold_falls_as_the_alternatives_of_a_rule_grow(alternatives, run, expected):
    assert _decision(alternatives, run) == expected, (alternatives, run)


# 4. Found in the review of the tenth round.
#
# A capital sigma at the end of a word lowers to the final sigma when the whole text is
# lowered, and to the medial one when the run is lowered on its own. The walk read only the
# second, so the word before a covered hit did not pair with the view and the hit blocked.
@pytest.mark.parametrize("route", sorted(ROUTES))
@pytest.mark.parametrize("lead", ["ΟΔΟΣ ", "Σ ", "ΟΣΟΣ ", "ΣΑΣ, ΟΔΟΣ ", "ΟΔΟΣ"])
def test_a_word_final_capital_sigma_before_a_covered_hit_keeps_it_covered(route, lead):
    result = ROUTES[route]().scan(lead.rstrip() + " " + COVERED, channel="message")
    assert result.decision == "allow_redacted" and _covered(result), (route, lead)


# A decimal reference of more than 4300 digits makes the pipeline's entity pass leave every
# entity in the text undecoded. The walk cannot pair an ordinary entity in front of a covered
# hit then, and ends there: the hit blocks, where main allows it. This is disclosed, and
# pinned here so that a change in either direction is seen. Only 4301 reaches this state: the
# base64 pass rewrites a reference of 5000 or 20000 digits.
@pytest.mark.parametrize("route", ["aho_keyword", "python_keyword", "normalized_regex"])
def test_an_entity_before_a_covered_hit_blocks_beside_a_4301_digit_reference_after_it(route):
    text = "&amp; " + COVERED + " &#" + "9" * 4301 + ";"
    result = ROUTES[route]().scan(text, channel="message")
    assert result.decision in BLOCKING and not _covered(result), route


@pytest.mark.parametrize("route", ["aho_keyword", "python_keyword", "normalized_regex"])
def test_the_same_entity_before_a_covered_hit_stays_covered_without_the_long_reference(route):
    result = ROUTES[route]().scan("&amp; " + COVERED, channel="message")
    assert result.decision == "allow_redacted" and _covered(result), route


# The normalizer measures the shadow view on its own, and the walk must pass that length to
# the views it keeps in front of it. Reading the lowered length instead lets a dotted
# capital I push a short view over the limit.
def _shadow_tail(dotted, folded):
    base = COVERED + " lamp " + "".join(chr(0xE0000 + ord(c)) for c in "a")
    measured = normalize_with_length(decode_shadow_ascii(base))[1]
    return base + "x" * (folded - measured - dotted) + "İ" * dotted


@pytest.mark.parametrize("route", ["aho_keyword", "python_keyword"])
@pytest.mark.parametrize("dotted", [1, 5, 20])
@pytest.mark.parametrize("folded", [ENRICH_MAX_LEN - 2, ENRICH_MAX_LEN - 1, ENRICH_MAX_LEN])
def test_a_covered_hit_beside_a_shadow_tail_near_the_limit_stays_covered(route, dotted, folded):
    text = _shadow_tail(dotted, folded)
    assert normalize_with_length(decode_shadow_ascii(text))[1] == folded
    result = ROUTES[route]().scan(text, channel="message")
    assert result.decision == "allow_redacted" and _covered(result), (route, dotted, folded)
