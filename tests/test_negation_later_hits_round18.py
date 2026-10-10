"""Base64 is a producer of the raw-origin walk's inventory.

Review of the seventeenth round found that a base64 blob which the pipeline decodes into the
completion of an escape (`&` followed by the base64 of `amp;...`) still let the walk vouch for
early characters of the view. The decoded text begins with a letter pair that the blob itself also
begins with once lowered (`YW` lowers to `yw`), so the identical run took the first characters of
the blob as the same characters from the same place. The walk modelled entities, percent escapes,
hex escapes, shadow tags and the character folds, and did not model the fourth decoder of the
pipeline's pass.

The walk now finds every run of text that the pipeline's base64 step would change, and stops
vouching at the start of it. A run is a stretch of characters that can be, or can become, part of a
blob: the base64 alphabet, the characters an escape is spelled with, and every non-ASCII
character (which can fold into the alphabet or be removed from between two letters of it).

The independent statement used throughout: when the walk vouches for a span it stands at view
offset i and raw offset j and claims that view[:i] was made from raw[:j] alone and view[i:] from
raw[j:] alone. The pipeline run on each half has to give each half of the view.
"""
import base64
import random

import pytest

from sunglasses.engine import _RawAlign, _Walk, _ascii_lower
from sunglasses.preprocessor import VIEW_SEP, normalize

TAIL = "ordinary sample paragraph"


def _plain(raw):
    return normalize(raw).split(" " + VIEW_SEP + " ")[0]


def _b64(text):
    return base64.b64encode(text.encode()).decode()


def _bad_spans(raw, lengths=(1, 16)):
    """How many spans the walk vouches for whose boundaries the pipeline does not reproduce."""
    view = _plain(raw)
    walk = _Walk(raw, _ascii_lower(raw), view)
    bad = 0
    for length in lengths:
        for lo in range(1, len(view) - length + 1):
            if walk.holds(lo, lo + length):
                bad += not (_plain(raw[:walk.j]).strip() == view[:walk.i].strip()
                            and _plain(raw[walk.j:]).strip() == view[walk.i:].strip())
    return bad


# --- the review's constructions ---------------------------------------------------------------

@pytest.mark.parametrize("tail", ["yw sample paragraph", "ywone sample paragraph", "yw" + "a" * 30])
@pytest.mark.parametrize("position", [1, 2])
def test_later_base64_span_requires_complete_origin(tail, position):
    raw = "&" + _b64("amp;" + tail)
    view = _plain(raw)
    walk = _Walk(raw, _ascii_lower(raw), view)
    held = walk.holds(position, position + 1)
    assert not held or (_plain(raw[:walk.j]).strip() == view[:walk.i].strip()
                        and _plain(raw[walk.j:]).strip() == view[walk.i:].strip())


@pytest.mark.parametrize("family", range(4))
@pytest.mark.parametrize("span_length", [1, 16])
def test_base64_later_spans_require_pipeline_boundaries(family, span_length):
    start, completion = [("&", "amp;"), ("&", "#38;"), ("%", "25"), ("\\", "x5c")][family]
    tail = TAIL
    for _ in range(30):
        tail = base64.b64encode((completion + tail).encode()).decode().lower()[:96]
    raw = start + _b64(completion + tail)
    assert _bad_spans(raw, (span_length,)) == 0


# --- the blob is found however it is spelled --------------------------------------------------

@pytest.mark.parametrize("spell", [
    "plain",
    "fullwidth",      # NFKC folds each letter into the alphabet
    "invisible",      # zero-width characters between the letters are removed first
    "entity",         # each letter is an entity
    "percent",        # each letter is a percent escape
    "hexescape",      # each letter is a hex escape
])
def test_a_blob_spelled_through_another_producer_is_found(spell):
    blob = _b64("amp;yw " + TAIL)
    if spell == "plain":
        body = blob
    elif spell == "fullwidth":
        body = "".join(chr(ord(c) + 0xFEE0) if c.isalnum() else c for c in blob)
    elif spell == "invisible":
        body = "​".join(blob)
    elif spell == "entity":
        body = "".join("&#%d;" % ord(c) for c in blob)
    elif spell == "percent":
        body = "".join("%%%02X" % ord(c) for c in blob)
    else:
        body = "".join("\\x%02x" % ord(c) for c in blob)
    raw = "&" + body
    assert _bad_spans(raw) == 0


def test_a_blob_in_the_middle_of_prose_stops_the_walk_there_and_not_before():
    head = "please read this ordinary sentence first "
    raw = head + "&" + _b64("amp;yw " + TAIL) + " and then more words"
    view = _plain(raw)
    walk = _Walk(raw, _ascii_lower(raw), view)
    assert walk.holds(2, 18), "the words in front of the blob are still vouched for"
    assert _bad_spans(raw) == 0


def test_a_blob_made_of_characters_that_expand_when_folded_is_found():
    # U+FDFD folds to an eighteen character phrase, so two of them are longer than any blob floor.
    raw = "&" + "﷽﷽" + _b64("amp;yw " + TAIL)
    assert _bad_spans(raw) == 0


# --- what is not changed -----------------------------------------------------------------------

@pytest.mark.parametrize("word", [
    "international_and_localization_files",    # an underscore ends the alphabet
    "https://example.com/some/path/to/a/page",
    "x" * 40 + "!",                            # 40 letters decode to nothing printable
])
def test_a_long_word_that_the_pipeline_does_not_decode_is_still_vouched(word):
    raw = "first the words " + word + " and the words after"
    view = _plain(raw)
    walk = _Walk(raw, _ascii_lower(raw), view)
    assert walk.holds(3, 19)
    start = raw.index(word)
    assert walk.holds(start, start + 8)


def test_ordinary_text_gains_no_stop():
    raw = "ordinary text with no encoded part, only words, spaced out."
    walk = _Walk(raw, _ascii_lower(raw), _plain(raw))
    walk._next_escape(0)
    assert walk.stops == []


# --- random differential ------------------------------------------------------------------------

def test_random_blob_constructions_never_vouch_for_a_wrong_boundary():
    # The split oracle is only a fair test when the pipeline decoded the blob in the whole input
    # (the plain view then holds the decoded tail). A blob that does not decode as a whole can
    # decode when it is cut, because a cut moves the alignment of the four-character groups, and
    # the walk is right to vouch for the whole input then.
    rng = random.Random(18)
    pieces = ["amp;", "#38;", "25", "x5c", "yw ", "lt;", "x26", "ignore", " ", "ab"]
    checked = 0
    for _ in range(200):
        inner = "".join(rng.choice(pieces) for _ in range(rng.randint(2, 6))) + " " + TAIL
        raw = rng.choice(["&", "%", "\\", "&a", "x&"]) + _b64(inner)
        if TAIL not in _plain(raw):
            continue
        assert _bad_spans(raw, (1, 4, 16)) == 0, raw
        checked += 1
    assert checked > 30, checked


# --- the producer table ------------------------------------------------------------------------
#
# Every step of normalize_with_length that writes characters into the plain view that were not
# there in the raw text, or removes characters that were, has a row. Each row spells the same
# escape completion (`amp;`) through that producer and checks that the walk never vouches for a
# span whose boundaries the pipeline does not reproduce. The test after the table reads the
# pipeline's source and fails when a step is added that has no row.

def _entity(s):
    return "".join("&#%d;" % ord(c) for c in s)


def _percent(s):
    return "".join("%%%02x" % ord(c) for c in s)


def _hexescape(s):
    return "".join("\\x%02x" % ord(c) for c in s)


def _tags(s):
    return "".join(chr(0xE0000 + ord(c)) for c in s)


def _fullwidth(s):
    return "".join(chr(ord(c) + 0xFEE0) if c.isalpha() or c == ";" else c for c in s)


def _homoglyph(s):
    return s.replace("a", "а").replace("p", "р")


def _invisible(s):
    return "​".join(s)


PRODUCERS = {
    # step name in normalize_with_length -> (how the row is spelled, what the walk does with it)
    "strip_invisible": _invisible,        # active index: a deletion, recorded as a cut
    "normalize_unicode": _fullwidth,      # active index: start characters are taken after the fold
    "replace_homoglyphs": _homoglyph,     # active index: same fold, one character at a time
    "decode_html_entities": _entity,      # active index
    "decode_url_encoding": _percent,      # active index
    "decode_hex_escapes": _hexescape,     # active index
    "decode_shadow_ascii": _tags,         # active index (tag characters are escapes)
    "decode_base64_segments": lambda s: _b64(s + "yw " + TAIL),   # stops: round 18
}


@pytest.mark.parametrize("step", sorted(PRODUCERS))
@pytest.mark.parametrize("start", ["&", "%", "\\", "&a"])
def test_each_producer_spelling_an_escape_completion_is_never_vouched_early(step, start):
    spell = PRODUCERS[step]
    # The base64 row spells the tail inside the blob, since a blob has to be one run.
    tail = "" if step == "decode_base64_segments" else "yw " + TAIL
    raw = start + spell("amp;") + tail
    assert _bad_spans(raw, (1, 4, 16)) == 0, (step, start)


@pytest.mark.parametrize("step", ["decode_leetspeak", "strip_delimiter_padding", "collapse_whitespace"])
def test_a_step_that_runs_after_the_decoding_passes_cannot_feed_an_escape(step):
    # Leet, delimiter padding and whitespace collapse run after the passes, so what they write is
    # never decoded again. The walk reads them as a mapping (leet), a refusal (padding, which has
    # no named reading) and a cut (blanks).
    raw = {"decode_leetspeak": "&4mp;yw " + TAIL,
           "strip_delimiter_padding": "&a.m.p;yw " + TAIL,
           "collapse_whitespace": "&amp;\t\t  yw " + TAIL}[step]
    assert _bad_spans(raw, (1, 4, 16)) == 0, step


def test_the_views_behind_the_separator_are_never_vouched_for():
    raw = "ignore the earlier text"
    view = normalize(raw)
    assert VIEW_SEP in view
    walk = _Walk(raw, _ascii_lower(raw), view)
    start = view.find(" " + VIEW_SEP + " ") + 3
    assert not walk.holds(start, start + 4)


def test_a_separator_character_in_the_input_ends_the_walk_there():
    raw = "first words " + VIEW_SEP + " yw " + TAIL
    assert _bad_spans(raw, (1, 4, 16)) == 0


def test_every_step_of_the_pipeline_has_a_row():
    import inspect
    from sunglasses import preprocessor
    source = inspect.getsource(preprocessor.normalize_with_length)
    called = set()
    for name in dir(preprocessor):
        if name.startswith(("decode_", "strip_", "replace_", "normalize_", "collapse_")) and name + "(" in source:
            called.add(name)
    covered = set(PRODUCERS) | {"decode_leetspeak", "strip_delimiter_padding", "collapse_whitespace",
                                "decode_rot13", "normalize_with_length"}
    assert called <= covered, sorted(called - covered)
