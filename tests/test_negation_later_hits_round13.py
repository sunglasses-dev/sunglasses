"""A reference whose terminator the pipeline removes or folds is not vouched for past its end.

Review of the twelfth round found that the raw walk accepted the prefix of a reference that the
decoder reads without its terminator. When the terminator was written with an invisible
character in front of it, or with a compatibility letter, the pipeline removed or folded it first
and then read the complete reference, so it used one raw character more than the walk did. The walk
then stood one raw character early and vouched for the text after the reference from the wrong place.
"""
import pytest

from sunglasses.engine import _RawAlign
from sunglasses.preprocessor import normalize_with_length

REFERENCES = {"named": ("&amp", "&"), "decimal": ("&#65", "a"), "hex": ("&#x41", "a")}
INVISIBLE = "​"
TERMINATORS = {
    "pad1": INVISIBLE + ";",
    "pad2": INVISIBLE * 2 + ";",
    "pad4": INVISIBLE * 4 + ";",
    "pad8": INVISIBLE * 8 + ";",
    "fullwidth": "；",
}
TAIL = ";;;;"


def _view_of(raw):
    return normalize_with_length(raw)[0].split(" \x1e ")[0]


def _case(prefix, reading, terminator):
    raw = "x " + prefix + terminator + TAIL + " end"
    view = _view_of(raw)
    lo = view.index(reading, 2) + 1
    assert view[lo:lo + len(TAIL)] == TAIL, (view, lo)
    return raw, view, lo


@pytest.mark.parametrize("terminator", sorted(TERMINATORS))
@pytest.mark.parametrize("kind", sorted(REFERENCES))
def test_the_text_after_a_reference_with_a_transformed_terminator_is_not_vouched_for(kind, terminator):
    prefix, reading = REFERENCES[kind]
    raw, view, lo = _case(prefix, reading, TERMINATORS[terminator])
    assert _RawAlign(raw).holds(view, lo, lo + len(TAIL)) is False


@pytest.mark.parametrize("kind", sorted(REFERENCES))
def test_the_text_before_such_a_reference_is_still_vouched_for(kind):
    prefix, reading = REFERENCES[kind]
    raw, view, lo = _case(prefix, reading, TERMINATORS["pad2"])
    assert _RawAlign(raw).holds(view, 0, 2) is True


@pytest.mark.parametrize("kind", sorted(REFERENCES))
def test_the_text_after_an_ordinary_reference_is_vouched_for(kind):
    prefix, reading = REFERENCES[kind]
    raw, view, lo = _case(prefix, reading, ";")
    assert _RawAlign(raw).holds(view, lo, lo + len(TAIL)) is True


@pytest.mark.parametrize("kind", sorted(REFERENCES))
def test_a_reference_without_a_terminator_before_ascii_text_is_still_followed(kind):
    prefix, reading = REFERENCES[kind]
    raw = "x " + prefix + " end"
    view = _view_of(raw)
    lo = view.index(reading, 2) + 1
    assert _RawAlign(raw).holds(view, lo, len(view)) is True


def test_text_that_only_looks_like_an_unfinished_reference_does_not_end_the_walk():
    raw = "R&D’s plan ;;;; end"
    view = _view_of(raw)
    lo = view.index(";;;;")
    assert _RawAlign(raw).holds(view, lo, lo + 4) is True
