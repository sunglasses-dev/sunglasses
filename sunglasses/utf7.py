"""UTF-7 runs, read the way a model reads them.

A model asked to "decode this UTF-7" will do it, and `+AEkAZwBuAG8AcgBl-` is `Ignore`. The
engine's own steps decode HTML entities, percent escapes and base64, but not this form, so a
sentence that blocks in plain text could pass when written as UTF-7. `utf7_view(text)` is the
text with each run that decodes to something readable replaced by that decode. The engine scans
the view in addition to the raw text, never instead of it (see `SunglassesEngine.scan`).

One level only: a run is decoded once and the view is never decoded again.

Cost: one linear pass. `+` is found with `str.find`, and the run after it is taken by one
anchored, greedy match of a single character class, so nothing backtracks. A bounded repeat in
that pattern was measured at 73.8 s on 1 MB of `+`, which is why there is none.
"""
import codecs
import collections
import re
import unicodedata

from .preprocessor import (IGNORABLE_RANGES, normalize_unicode, replace_homoglyphs, replace_lookalikes,
                           strip_ignorable, strip_invisible)

# The base64 alphabet of the codec. A `+` inside a run is a base64 digit, as in the real codec.
_BODY = re.compile("[A-Za-z0-9+/]*")

# One UTF-16 unit needs three base64 letters. A larger minimum is an evasion lever: an attacker
# splits the payload into short runs, so a minimum of 16 loses "one letter encoded" and "split".
MIN_BODY = 3

# Bodies shorter than this are decoded strictly (see `utf7_view`).
STRICT_BELOW = 8

# No cap on spans or decoded length, on purpose. The engine cuts its input at `max_scan_bytes` before
# the view is built, and a view is never longer than its input. A smaller cap is an evasion lever:
# flood the text with harmless runs, put the payload after the cap.
_FOLD_NONASCII = {}   # answers of `_folds_to_ascii`, kept for the process (bounded, see below)


def _folds_to_ascii(char):
    """True for a character the engine itself reads as ASCII before it matches: any of its four folded
    views (`_fold_text`, `_compact_text`, `_wide_fold_text`, `_wide_compact_text` in engine.py) turns it
    into ASCII, taken with the engine's own functions and in the engine's own order (compatibility
    folding first, then the look alike map), never a copy of either. A character a fold deletes (an
    invisible one) is not ASCII, it is nothing. Decoding such a character cannot show the engine
    anything it does not already read the same way from the raw text."""
    hit = _FOLD_NONASCII.get(char)
    if hit is None:
        hit = any(r and r.isascii() for r in (
            replace_homoglyphs(normalize_unicode(strip_invisible(char))),
            replace_homoglyphs(strip_invisible(char)),
            replace_lookalikes(normalize_unicode(strip_ignorable(char))),
            replace_lookalikes(strip_ignorable(char))))
        if len(_FOLD_NONASCII) < 4096:
            _FOLD_NONASCII[char] = hit
    return hit


# A lone surrogate is not a character at all (UTF-16 half left over by the codec) and is the only thing the view drops.
# Private use and unassigned code points stay in the text: the view is the faithful decode.
_SURROGATES = re.compile("[\ud800-\udfff]")

# Neutral characters: controls, spaces and the characters that render as nothing. Written as code point ranges, never read from
# unicodedata, so the set is the same on every Python the package supports (a character newer than the interpreter's Unicode
# tables is the same answer there). The invisible ranges are the engine's own (preprocessor.IGNORABLE_RANGES).
_SPACE_RANGES = ((0x20, 0x20), (0xA0, 0xA0), (0x1680, 0x1680), (0x2000, 0x200A), (0x202F, 0x202F), (0x205F, 0x205F), (0x3000, 0x3000))
_NEUTRAL = re.compile("[" + "".join("%s-%s" % (re.escape(chr(lo)), re.escape(chr(hi)))
                                    for lo, hi in ((0x00, 0x1F), (0x7F, 0x9F)) + _SPACE_RANGES + IGNORABLE_RANGES) + "]")


def _is_neutral(char):
    return _NEUTRAL.match(char) is not None


_KANA_HAN = ("CJK", "HIRAGANA", "KATAKANA")


def _script(char):
    """A coarse script key: the first word of the character name, with Han and kana as one script (Japanese)."""
    word = unicodedata.name(char, "?").split(" ", 1)[0]
    return "CJK" if word in _KANA_HAN else word


# Characters in a row, ASCII or folding to ASCII, that make a decode with a mix of scripts text (see `read_run`).
ASCII_STRETCH = 4


def _has_ascii_stretch(text):
    """True when `text` holds ASCII_STRETCH or more characters in a row that are ASCII or fold to ASCII. A neutral character (a space,
    a control, a zero width joiner, a no break space, ASCII or not) sits inside the stretch without counting and without breaking it."""
    run = 0
    for c in text:
        if _is_neutral(c):
            continue
        if c.isascii() or _folds_to_ascii(c):
            run += 1
            if run >= ASCII_STRETCH:
                return True
        else:
            run = 0
    return False


def read_run(decoded):
    """The text of one decoded run as it goes into the view, or None when the run is not text.

    Judged per character, never the whole run: a newline, a tab, a zero width
    joiner or a no break space inside a run used to make the whole run "not printable" and hide a full
    sentence a model still reads. The view is the faithful decode: the only thing removed is a lone surrogate (a UTF-16
    half the codec left over), by code point range. Private use and unassigned characters stay and count as "other"
    below (no category table decides what is deleted, so no Python version does). Then one of:
    - every character is ASCII, a neutral one (control, space, invisible: pinned code point ranges) or one the engine
      folds to ASCII (see `_folds_to_ascii`), at any length. English written in UTF-7 decodes to ASCII,
      and a lone look alike letter (`+BD4-` is Cyrillic o) is exactly how a sentence is split;
    - at least 8 characters, at least 60 percent of the decode letters or neutral characters, at most 20 percent of the decode
      lone surrogates, and either at least 80 percent of the non-ASCII ones in one script or a stretch of 4 characters in a row that
      are ASCII or fold to ASCII (a sentence with a few letters of other scripts in it): other scripts, long runs only, so a random
      base64 looking token is not taken for text. KNOWN LIMIT: "letter" and "script" come from the interpreter's Unicode tables, so a
      letter newer than the tables (Python 3.9 knows Unicode 13) is not a letter there; the ASCII and neutral paths above do not
      depend on the tables.
    Nothing left after the surrogates are removed is not text.
    """
    if not decoded:
        return None
    if decoded.isascii():
        return decoded
    text = _SURROGATES.sub("", decoded)
    if not text:
        return None
    if all(c.isascii() or _is_neutral(c) or _folds_to_ascii(c) for c in text):
        return text
    # Other scripts, long runs only. Random base64 looking text decodes to units spread over the whole plane
    # (CJK, Hangul, Yi, private use, unassigned), and most of those are letters, so "mostly letters" alone
    # cannot tell it from text. Real text in another script stays in one script, so that is required too.
    # The share of letters is taken over what was DECODED, so a surrogate removed above counts against the run.
    if len(text) < 8 or len(text) < 0.8 * len(decoded):
        return None
    if sum(1 for c in text if c.isalpha() or _is_neutral(c)) / len(decoded) < 0.6:
        return None
    scripts = collections.Counter(_script(c) for c in text if not c.isascii() and not _is_neutral(c))
    if scripts and max(scripts.values()) / sum(scripts.values()) >= 0.8:
        return text
    # A sentence with a few letters of other scripts in the same run (tail, head or middle) fails the one script test above, and
    # a model still reads the sentence. So a stretch of ASCII_STRETCH characters in a row that are ASCII
    # or fold to ASCII is also text. Random base64 looking text has no such stretch: a unit is ASCII or folds to ASCII about 1 time in 300.
    if _has_ascii_stretch(text):
        return text
    return None


def utf7_view(text):
    """`text` with every accepted UTF-7 run replaced by its decode, or None when no run was.

    None is the ordinary answer (no corpus text, commit diff or repo file built a view), and the
    caller then returns the raw result untouched. A run is `+`, a body of base64 letters, and one
    closing `-` if there is one. `+-` is the literal plus and is never decoded.
    """
    out, last, n = [], 0, len(text)
    i = text.find("+")
    while i != -1:
        end = _BODY.match(text, i + 1).end()
        stop = end + 1 if end < n and text[end] == "-" else end
        if end - (i + 1) >= MIN_BODY:
            # A body of 8 letters or more is decoded with errors="ignore": a stray base64 letter at the end of a run is
            # a "partial character" to the strict decoder, which then refuses the whole run, while a model reads
            # everything before it. A shorter body is decoded strictly: measured on 300 commit diffs, an
            # identifier after a plus (`+ALL_FIRES`) is a 3 to 5 letter body whose leftover bits are not zero, and
            # with "ignore" 17 of them built a view for no reason.
            body = text[i + 1:end]
            try:
                decoded = read_run(codecs.decode(("+" + body + "-").encode("ascii"), "utf-7",
                                                 "ignore" if len(body) >= STRICT_BELOW else "strict"))
            except UnicodeError:
                decoded = None
            if decoded is not None:
                out.append(text[last:i])
                out.append(decoded)
                last = stop
        i = text.find("+", stop)
    if not out:
        return None
    out.append(text[last:])
    return "".join(out)
