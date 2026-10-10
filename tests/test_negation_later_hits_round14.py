"""A reading made by layers of decoding is not vouched for at a raw position the layers could have moved.

Review of the thirteenth round found nine independent cases where the raw walk vouched for text
that stood a few raw characters early: a percent-encoded reference whose decoded form is completed
by the raw text after it (`%26amp%3B` followed by `amp;`), and a short unchanged tail after nested
references. The checks had been added one shape at a time at three sites. The walk now asks one
question of every reading it accepts: is the reading a fixed point of the pipeline's own decoding,
including at its right edge, where the next raw characters could complete it?
"""
import random

import pytest

from sunglasses.engine import _RawAlign
from sunglasses.preprocessor import normalize_with_length

SEP = " \x1e "


def _view_of(raw):
    return normalize_with_length(raw)[0].split(SEP)[0]


def _percent(text):
    return "".join("%" + format(ord(c), "02X") for c in text)


def _exact(align, view, lo, hi, expected_raw_end):
    """The span is either not vouched for, or vouched for at exactly the raw end the pipeline used."""
    if not align.holds(view, lo, hi):
        return True
    walk = align._walks[id(view)]
    return walk.i == hi and walk.j == expected_raw_end


@pytest.mark.parametrize("lead", ["", "x ", "xx ", "xyz "])
@pytest.mark.parametrize("layers", [0, 1, 2])
def test_percent_encoded_reference_completed_by_the_raw_tail(lead, layers):
    source = lead + "&" + "amp;" * layers
    prefix = _percent(source)
    tail = "amp;" * 40 + " end"
    raw = prefix + tail
    view = _view_of(raw)
    extra = 4 * (2 - layers)
    assert view == lead + "&" + tail[extra:]
    lo = len(source) + 4
    hi = lo + 16
    actual = len(prefix) + extra + hi - len(lead) - 1
    assert _exact(_RawAlign(raw), view, lo, hi, actual)


@pytest.mark.parametrize("kind,outer", [("named", "&amp;"), ("decimal", "&#38;"), ("hex", "&#x26;")])
@pytest.mark.parametrize("width", [1, 2])
@pytest.mark.parametrize("layers", [0, 1, 2])
def test_short_unchanged_tail_after_nested_references(kind, outer, width, layers):
    middle = "amp;"
    tail = middle[:width] + "z trailing prose"
    raw = outer + middle * layers + tail
    view = _view_of(raw)
    assert view == "&" + tail
    actual = len(outer) + len(middle) * layers + width
    assert _exact(_RawAlign(raw), view, 1, 1 + width, actual)


@pytest.mark.parametrize("window", [64, 65, 200])
def test_a_long_run_of_completing_text_still_ends_the_walk(window):
    raw = "%26" + "amp;" * (window // 4 + 4) + " end of the text here"
    view = _view_of(raw)
    assert _RawAlign(raw).holds(view, 3, 8) is False


@pytest.mark.parametrize("ref", ["&amp", "&#65", "&#x41"])
@pytest.mark.parametrize("follow", ["é", "\xa0", "’", "“", "—", "ß"])
def test_an_ordinary_unterminated_reference_followed_by_non_ascii_is_still_vouched_for(ref, follow):
    raw = "x " + ref + follow + " tail words after the reference here and more"
    view = _view_of(raw)
    lo = view.index("tail")
    align = _RawAlign(raw)
    assert align.holds(view, lo, lo + 4) is True
    assert align.holds(view, 0, 2) is True


@pytest.mark.parametrize("raw", [
    "x &amp; and then plain words that follow it here",
    "x %41 and then plain words that follow it here",
    "x &#65; and then plain words that follow it here",
    "plain words only, nothing encoded at all, long enough to scan",
])
def test_one_layer_and_plain_text_are_still_vouched_for(raw):
    view = _view_of(raw)
    lo = view.index("plain") if raw.startswith("plain") else view.index("and")
    assert _RawAlign(raw).holds(view, lo, lo + 3) is True


@pytest.mark.parametrize("ref,reading", [("&amp", "&"), ("&#65", "a"), ("&#x41", "a")])
@pytest.mark.parametrize("terminator", ["​;", "​​;", "；"])
def test_a_hidden_terminator_still_ends_the_walk(ref, reading, terminator):
    raw = "x " + ref + terminator + ";;;; end"
    view = _view_of(raw)
    lo = view.index(reading, 2) + 1
    assert _RawAlign(raw).holds(view, lo, lo + 4) is False


def _pct(text, rng, p):
    return "".join("%%%02X" % ord(c) if rng.random() < p else c for c in text)


def _generate(rng):
    kind = rng.choice(["pct", "ent", "mix"])
    lead = rng.choice(["", "x ", "xx ", "ab "])
    inner = rng.choice(["&amp;", "&#38;", "&#x26;", "&amp", "&", "%26", "&lt;", "%25"])
    layers = rng.randint(0, 3)
    middle = rng.choice(["amp;", "#38;", "lt;", "26", "x26;"])
    source = lead + inner + middle * layers
    if kind == "pct":
        head = _pct(source, rng, rng.choice([0.5, 1.0]))
    elif kind == "ent":
        head = "".join("&#%d;" % ord(c) if rng.random() < 0.5 else c for c in source)
    else:
        head = rng.choice(["＆", "&amp;", "%26"]) + source
    tail = rng.choice(["amp;", "lt;", "z ", "mp;", "x26;", "a"]) * rng.randint(1, 6) + " end of the text here"
    return head + tail


@pytest.mark.parametrize("seed", [1, 7, 99])
def test_every_vouch_matches_the_raw_text_the_pipeline_needs(seed):
    """Whatever shape the layers take, the walk's raw end is the raw length the pipeline needs for the view so far."""
    rng = random.Random(seed)
    for _ in range(400):
        raw = _generate(rng)
        view = _view_of(raw)
        align = _RawAlign(raw)
        for hi in range(1, len(view) + 1):
            lo = max(0, hi - 4)
            if align.holds(view, lo, hi):
                walk = align._walks[id(view)]
                got = _view_of(raw[:walk.j])
                assert got.rstrip() == view[:walk.i].rstrip(), (raw, view, lo, hi, walk.i, walk.j, got)
                break
