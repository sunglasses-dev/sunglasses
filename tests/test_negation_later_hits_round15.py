"""A reading whose escape is completed past the lookahead window is not vouched for.

Review of the fourteenth round found 48 cases where the walk vouched for a short unchanged interval
four raw characters early: a reading that is the start of an escape (`&` from `%26`, `\x26`, `&#38;`
or the full width ampersand), then more invisible characters than the lookahead holds (64), then the
rest of the escape (`amp;`) and ordinary text. The pipeline removes the invisible characters first, so
it reads `&amp;az`; the lookahead saw only the padding, so the escape looked finished, and the walk
stood on the `a` of `amp;` instead of the `a` of `az`.

The check that came with the fourteenth round stopped at the first span the walk accepted, asked for
spans in one order, and did not generate padding. This round asks for every span on its own fresh walk
(a walk that has already moved on can hide a wrong start), builds the padding, and checks that the raw
end the walk reports is not earlier than the shortest raw text from which the pipeline makes the view
up to there. Spans are asked for in a window of four characters behind each end of a short view, so
this is a check of the spans the walk is given and not of every span of an arbitrary text.
"""
import pytest

from sunglasses.engine import _RawAlign
from sunglasses.preprocessor import VIEW_SEP, normalize_with_length

FAMILIES = {"percent": "%26", "hex": "\\x26", "entity": "&#38;", "folded": "＆"}
PADDING = {"zero width space": 0x200B, "word joiner": 0x2060, "byte order mark": 0xFEFF,
           "soft hyphen": 0xAD}
LENGTHS = [0, 1, 63, 64, 65, 128]


def _view_of(raw):
    return normalize_with_length(raw)[0].split(" " + VIEW_SEP + " ")[0]


def _needed_raw_end(raw, view, i):
    """The shortest raw prefix from which the pipeline makes the first i characters of the view."""
    want = view[:i].rstrip()
    for j in range(1, len(raw) + 1):
        if _view_of(raw[:j]).rstrip() == want:
            return j
    return len(raw) + 1


def _vouched_spans_stand_no_earlier_than_the_pipeline_needs(raw):
    view = _view_of(raw)
    accepted = 0
    for hi in range(1, len(view) + 1):
        for lo in range(max(0, hi - 4), hi):
            align = _RawAlign(raw)
            if align.holds(view, lo, hi):
                accepted += 1
                walk = align._walks[id(view)]
                needed = _needed_raw_end(raw, view, walk.i)
                assert walk.j >= needed, (raw[:12], len(raw), lo, hi, walk.i, walk.j, needed)
    return accepted


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("padding", PADDING)
@pytest.mark.parametrize("length", LENGTHS)
def test_an_escape_completed_past_the_window_does_not_move_the_raw_origin(family, padding, length):
    prefix = FAMILIES[family]
    raw = prefix + chr(PADDING[padding]) * length + "amp;az trailing prose"
    view = _view_of(raw)
    assert view == "&az trailing prose"
    align = _RawAlign(raw)
    if align.holds(view, 1, 2):
        walk = align._walks[id(view)]
        assert (walk.i, walk.j) == (2, len(prefix) + length + 5)


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("length", [0, 63, 64, 65, 128])
def test_every_span_after_an_over_window_escape_is_vouched_for_at_its_true_end(family, length):
    raw = "x " + FAMILIES[family] + "​" * length + "amp;az trailing prose"
    _vouched_spans_stand_no_earlier_than_the_pipeline_needs(raw)


@pytest.mark.parametrize("length", [0, 63, 64, 65, 128])
def test_an_escape_finished_inside_the_window_is_still_read(length):
    """Control: the escape is complete before the padding, so the text after it is read as before."""
    raw = "x &#38;amp;" + "​" * length + "az trailing prose"
    assert _vouched_spans_stand_no_earlier_than_the_pipeline_needs(raw) > 0


def test_plain_text_that_ends_a_window_in_a_name_is_read():
    """Control: a reading with no escape start in it does not depend on how a cut window ends."""
    raw = "x " + "a" * 60 + " &am" + "z" * 40 + " and then a plain tail of the text"
    assert _vouched_spans_stand_no_earlier_than_the_pipeline_needs(raw) > 0
