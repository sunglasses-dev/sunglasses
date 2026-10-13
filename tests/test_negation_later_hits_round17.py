"""The candidate set of the raw-origin walk is every start character, taken one character at a time.

Review of the sixteenth round found 18 of 72 constructions where the walk still stood on raw offset
2 for a view that the pipeline made from a longer stretch. In each, the reference is `&a` followed
by an interior escape that is itself spelled with a character that folds to an escape start (a
full-width or small percent sign, backslash or ampersand), followed by ordinary words. The walk
looked for escapes with a regular expression over the raw text, which selects only the ASCII starts,
so the folded start was not in its index; no escape was active, no start character was a guard, and
the identical run took `&a` as unchanged text.

The candidate set is now every raw character that is, or folds to, an escape start. It is built
from the same character steps the pipeline runs, one character at a time, and three tests below
check that this is complete: every code point is classified, none of the three starts is made or
lost by composing or reordering characters, and a random differential test compares the walk with
an independent statement of what it claims.

The independent statement: when the walk vouches for a span it stands at view offset i and raw
offset j and claims that view[:i] was made from raw[:j] alone and view[i:] from raw[j:] alone. The
pipeline run on each half has to give each half of the view.
"""
import random
import unicodedata

import pytest

from sunglasses.engine import _RawAlign, _Walk, _folds_to_a_start
from sunglasses.preprocessor import (VIEW_SEP, normalize_unicode, normalize_with_length,
                                     replace_homoglyphs, strip_invisible)

TAIL = "az trailing prose"
STARTS = "&%\\"
TAGS = range(0xE0020, 0xE007F)


def _view_of(raw):
    return normalize_with_length(raw)[0].split(" " + VIEW_SEP + " ")[0]


def _fold(c):
    return replace_homoglyphs(normalize_unicode(strip_invisible(c)))


# --- the extent of a reference with a folded interior start -----------------------------------

@pytest.mark.parametrize("outer", [0x26, 0xFF06, 0xFE60], ids=["ascii", "fullwidth", "small"])
@pytest.mark.parametrize("inner", ["%6d", "％6d", "﹪6d", "＼x6d", "﹨x6d", "＆#109;",
                                   "﹠#109;"],
                         ids=["percent", "fullwidth-percent", "small-percent", "fullwidth-hex",
                              "small-backslash-hex", "fullwidth-entity", "small-entity"])
@pytest.mark.parametrize("blank", ["", " ", " ", "​"], ids=["none", "line", "paragraph", "zws"])
@pytest.mark.parametrize("depth", [2, 3])
def test_a_span_after_a_reference_with_a_folded_interior_stands_at_the_end_of_the_reference(
        outer, inner, blank, depth):
    reference = chr(outer) + "a" + inner[:1] + blank + inner[1:] + "p;" + ("amp;" if depth == 3 else "")
    raw = reference + TAIL
    view = _view_of(raw)
    assert view == "&" + TAIL
    align = _RawAlign(raw)
    if align.holds(view, 1, 2):
        walk = align._walks[id(view)]
        assert walk.i == 2 and walk.j == len(reference) + 1


# --- the candidate set is complete ----------------------------------------------------------

def test_every_code_point_that_folds_to_a_start_is_a_candidate_and_no_other_is():
    flagged = []
    for cp in range(0x80, 0x110000):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        c = chr(cp)
        folds = any(x in STARTS for x in _fold(c))
        assert _Walk._candidate(c) == (folds or cp in TAGS), hex(cp)
        assert _folds_to_a_start(c) == folds, hex(cp)
        if folds:
            flagged.append(cp)
    # The six are the full-width and small forms; a change in the Unicode tables that adds one is
    # picked up by the loop above, and this line only says what the set is today.
    assert flagged == [0xFE60, 0xFE68, 0xFE6A, 0xFF05, 0xFF06, 0xFF3C]


def test_the_ascii_starts_and_the_shadow_characters_are_candidates():
    for c in STARTS:
        assert _Walk._candidate(c)
    for cp in TAGS:
        assert _Walk._candidate(chr(cp))
    for c in "a1 ;#é́":
        assert not _Walk._candidate(c)


def test_no_start_is_made_or_lost_by_composing_or_reordering_characters():
    # Folding one character at a time finds every start only if none of the three is made by a
    # composition (it would have a canonical decomposition, or be the product of a pair) and none
    # is combined into another character (it would be the second member of a pair).
    for c in STARTS:
        assert unicodedata.decomposition(c) == ""
        assert unicodedata.combining(c) == 0
    pairs = 0
    for cp in range(0x80, 0x110000):
        d = unicodedata.decomposition(chr(cp))
        if d and not d.startswith("<"):
            parts = [int(x, 16) for x in d.split()]
            pairs += len(parts) == 2
            assert not any(chr(p) in STARTS for p in parts), hex(cp)
    assert pairs > 900


def test_a_folded_start_inside_an_entity_is_in_the_index_and_so_is_the_start_in_front_of_it():
    raw = "&a％6dp;" + TAIL
    walk = _Walk(raw, raw.lower(), _view_of(raw))
    walk._next_escape(0)
    assert 2 in walk.active, walk.active
    assert 0 in walk.guards, walk.guards


# --- a differential test against an independent statement of what the walk claims -------------

ATOMS = ["&", "%", "\\", "&", "%", "a", "m", "p", ";", "#", "x", "6", "d", "2", "3", "amp;", "lt;", "%26", "%6d",
         "\\x26", "&#38;", "&amp;", "&#109;", "q", "z", "k", "u", "4",
         "＆", "％", "＼", "﹠", "﹨", "﹪", "Ｆ", "ｅ", "ａ",
         "​", "⁠", "﻿", " ", " ", "­", "\U000e0026", "\U000e0025", "\U000e0061",
         "́", "α", "а", "K", "ẞ", "é"]
OUTER = ["&", "&", "＆", "﹠", "%", "\\"]
LETTERS = ["a", "l", "g", "am", "a", "#", "#1", "x"]
INTERIOR = ["%6d", "％6d", "﹪6d", "＼x6d", "﹨x6d", "＆#109;", "﹠#109;", "&#109;",
            "\\x6d", "%26", "＆26", "%2", "％2"]
PAD = ["​", "⁠", "﻿", " ", " ", "­", "\U000e0020"]
DONE = ["p;", "p", "amp;", "", ";", "mp;"]


def _structured(rng):
    parts = [rng.choice(OUTER), rng.choice(LETTERS), rng.choice(INTERIOR), rng.choice(DONE)]
    if rng.random() < 0.4:
        parts.insert(rng.randint(1, len(parts)), rng.choice(OUTER))
    out = []
    for ch in "".join(parts):
        out.append(ch)
        if rng.random() < 0.25:
            out.append(rng.choice(PAD) * rng.randint(1, 3))
    return "".join(out) + (rng.choice(["amp;", "p;", ""]) if rng.random() < 0.4 else "")


def _raw(rng):
    if rng.random() < 0.6:
        head = _structured(rng)
        if rng.random() < 0.3:
            head = "".join(rng.choice(ATOMS) for _ in range(rng.randint(1, 3))) + head
        return head + rng.choice(["", TAIL, "az", "p;az", "az trailing"])
    return "".join(rng.choice(ATOMS) for _ in range(rng.randint(2, 11))) + rng.choice(["", TAIL, "az", "p;az"])


def _violations(raws):
    bad, vouched = [], 0
    for raw in raws:
        view = _view_of(raw)
        if view == raw or not view:
            continue
        align = _RawAlign(raw)
        for hi in range(1, len(view) + 1):
            for lo in range(max(0, hi - 3), hi):
                if not align.holds(view, lo, hi):
                    continue
                vouched += 1
                walk = align._walks[id(view)]
                i, j = walk.i, walk.j
                before = _view_of(raw[:j]).strip(" ")
                after = _view_of(raw[j:]).strip(" ")
                if before != view[:i].strip(" ") or after != view[i:].strip(" "):
                    bad.append((raw, lo, hi, i, j))
                    break
            else:
                continue
            break
    return bad, vouched


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_a_vouched_span_splits_the_raw_text_where_it_splits_the_view(seed):
    rng = random.Random(seed)
    bad, vouched = _violations([_raw(rng) for _ in range(500)])
    assert vouched > 5000
    assert bad == [], bad[:3]


def test_the_differential_test_finds_the_defect_it_was_written_for(monkeypatch):
    # The same test on a walk that indexes only the ASCII starts, as the sixteenth round did.
    monkeypatch.setattr(_Walk, "_candidate", staticmethod(lambda c: c in STARTS or c in map(chr, TAGS)))
    monkeypatch.setattr(__import__("sunglasses.engine", fromlist=["x"]), "_folds_to_a_start",
                        lambda c: False)
    rng = random.Random(1)
    bad, _ = _violations([_raw(rng) for _ in range(1500)])
    assert len(bad) >= 5


# --- the review's own 72 constructions, kept as they were reported ------------------------------

@pytest.mark.parametrize("outer", [38, 0xFF06, 0xFE60], ids=["ascii", "fullwidth", "small"])
@pytest.mark.parametrize("inner", [0, 1, 2, 3],
                         ids=["plain_percent", "folded_percent", "folded_hex", "folded_entity"])
@pytest.mark.parametrize("blank", [0, 0x2028, 0x2029], ids=["none", "line_separator", "paragraph_separator"])
@pytest.mark.parametrize("depth", [2, 3])
def test_the_reviewed_constructions_stand_at_the_end_of_the_reference(outer, inner, blank, depth):
    interiors = ["%6d", chr(0xFF05) + "6d", chr(0xFF3C) + "x6d", chr(0xFF06) + "#109;"]
    enc = interiors[inner]
    pad = chr(blank) if blank else ""
    reference = chr(outer) + "a" + enc[:1] + pad + enc[1:] + "p;" + ("amp;" if depth == 3 else "")
    raw = reference + TAIL
    view = _view_of(raw)
    assert view == "&" + TAIL
    align = _RawAlign(raw)
    if align.holds(view, 1, 2):
        walk = align._walks[id(view)]
        assert walk.i == 2 and walk.j == len(reference) + 1
