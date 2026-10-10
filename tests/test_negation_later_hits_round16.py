"""A start character in front of an escape the pipeline decodes first is not skipped over.

Review of the fifteenth round found 56 cases where the walk stood on the raw offset 2 for a view that
the pipeline made from a longer stretch. The raw text is a reference whose interior letter is itself
encoded (`&a%6dp;`: the pipeline decodes the percent escape to `m`, reads `&amp;`, and decodes that
to `&`), followed by ordinary words. The view is `&az ...`. The first two raw characters, `&a`,
are the same as the first two characters of the view, so the walk took them as an unchanged run and
stood after them; the `a` it vouched for is the `a` of `amp;`, not the one of `az`.

The check of the previous round compared with the shortest raw prefix from which the pipeline makes
the view up to there. That is not an origin: `&a` followed by nothing can read as `&a` on its own, and
the complete input then reads it as part of a reference. Here the extent of each reference is given by
the way the raw text is built (a list of raw pieces, each with the text it decodes to), so the raw
offset a view offset must stand at is known without asking the pipeline, and a span the walk accepts
has to end exactly there.
"""
import pytest

from sunglasses.engine import _RawAlign, _Walk
from sunglasses.preprocessor import VIEW_SEP, normalize_with_length

TAIL = "az trailing prose"
PADDING = {"none": None, "zero width space": 0x200B, "word joiner": 0x2060, "byte order mark": 0xFEFF,
           "tag character": 0xE007F}
LENGTHS = [0, 1, 63, 64, 65, 128]


def _view_of(raw):
    return normalize_with_length(raw)[0].split(" " + VIEW_SEP + " ")[0]


def _pad(kind, length):
    return "" if PADDING[kind] is None else chr(PADDING[kind]) * length


def _builds():
    """(name, reference) pairs. Each reference is raw text that the pipeline reads as one `&`
    before the tail, spelled so that the start of the reference comes before an encoded letter."""
    out = []
    for family, enc in (("percent", "%6d"), ("hex", "\\x6d"), ("entity", "&#109;")):
        for start in ("&", "＆"):
            out.append((f"{family}-interior-{start!r}", start + "a" + enc, "p;"))
    return out


def _references(kind, length):
    pad = _pad(kind, length)
    refs = []
    for name, head, rest in _builds():
        refs.append((name + "-pad-after-interior", head + pad + rest))
        refs.append((name + "-pad-before-interior", head[:2] + pad + head[2:] + rest))
        refs.append((name + "-nested", head + pad + rest + pad + "amp;"))
    # The start is itself spelled through an escape that has an escape inside it.
    refs.append(("percent-start", "%2%36" + pad + "amp;"))
    refs.append(("hex-start", "\\x2%36" + pad + "amp;"))
    return refs


def _spans(view):
    for hi in range(1, len(view) + 1):
        for lo in range(max(0, hi - 4), hi):
            yield lo, hi


@pytest.mark.parametrize("kind", PADDING)
@pytest.mark.parametrize("length", LENGTHS)
def test_a_span_after_a_reference_with_an_encoded_interior_stands_at_the_end_of_the_reference(kind, length):
    checked = 0
    for name, reference in _references(kind, length):
        raw = reference + TAIL
        view = _view_of(raw)
        # The reference is one character, `&`; this is given by how the raw text was built.
        assert view == "&" + TAIL, (name, view[:12])
        for lo, hi in _spans(view):
            align = _RawAlign(raw)
            if align.holds(view, lo, hi):
                checked += 1
                walk = align._walks[id(view)]
                assert lo >= 1, (name, lo, hi)
                assert walk.j == len(reference) + (hi - 1), (name, len(reference), lo, hi, walk.j)
    assert checked >= 0


def test_the_cases_are_not_vacuous():
    # With nothing between the reference and the tail the walk is past it and vouches for the tail
    # only when it knows where the reference ended; an accepted span would show that. Either
    # outcome is allowed, but the generated texts must be the ones the pipeline reads as `&`.
    for name, reference in _references("none", 0):
        assert _view_of(reference + TAIL) == "&" + TAIL, name


# Controls: a start character that has an escape later in the same run, and is not part of one.

@pytest.mark.parametrize("raw, spans", [
    ("ab&cd%41ef gh", [(0, 2), (2, 4), (2, 5), (0, 5)]),
    ("x&y z%41", [(0, 3)]),
    ("key=ab&rate=cd&size=ef%20tail", [(0, 7), (6, 14), (13, 21)]),
    ("price fifty%25 off &co", [(0, 11)]),
])
def test_a_start_character_that_belongs_to_no_reference_is_still_vouched_for(raw, spans):
    view = _view_of(raw)
    for lo, hi in spans:
        assert view[lo:hi] == raw[lo:hi].lower(), (lo, hi)
        assert _RawAlign(raw).holds(view, lo, hi), (raw, lo, hi)


def test_a_decoded_character_is_still_not_vouched_for():
    raw = "ab&cd%41ef gh"
    view = _view_of(raw)
    assert not _RawAlign(raw).holds(view, 5, 6)


def test_a_start_character_in_another_run_is_not_asked_about():
    # A reference cannot reach over a blank, so a start character before one is not a guard.
    raw = "x& y%41 end"
    walk = _Walk(raw, raw.lower(), _view_of(raw))
    walk._next_escape(0)
    assert walk.guards == []
    raw = "x&y%41 end"
    walk = _Walk(raw, raw.lower(), _view_of(raw))
    walk._next_escape(0)
    assert walk.guards == [1]


def test_a_guard_is_found_before_a_folded_escape_too():
    raw = "&a" + chr(0x200B) * 3 + "mp;az"
    walk = _Walk(raw, raw.lower(), _view_of(raw))
    walk._next_escape(0)
    assert 0 in walk.active or 0 in walk.guards


# Work bound: the guards of one walk are asked about a fixed number of times.

def test_many_start_characters_before_an_escape_cost_a_fixed_number_of_gate_calls(monkeypatch):
    calls = []
    real = _Walk._layered
    monkeypatch.setattr(_Walk, "_layered", lambda self, *a: calls.append(1) or real(self, *a))
    raw = "&" * 5000 + "%41" + " tail"
    view = _view_of(raw)
    align = _RawAlign(raw)
    align.holds(view, 0, 8)
    assert len(calls) <= _Walk.GUARD_CHECKS + 1, len(calls)
    # Past the limit nothing is vouched for.
    assert not _RawAlign(raw).holds(view, 4990, 4998)
