"""UTF-7 runs, read the way a model reads them (C1191).

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
import re
import unicodedata

from .preprocessor import HOMOGLYPHS

# The base64 alphabet of the codec. A `+` inside a run is a base64 digit, as in the real codec.
_BODY = re.compile("[A-Za-z0-9+/]*")

# One UTF-16 unit needs three base64 letters. A larger minimum is an evasion lever: an attacker
# splits the payload into short runs, so a minimum of 16 loses "one letter encoded" and "split".
MIN_BODY = 3

# No cap on spans or decoded length, on purpose. The engine cuts its input at `max_scan_bytes` before
# the view is built, and a view is never longer than its input. A smaller cap is an evasion lever:
# flood the text with harmless runs, put the payload after the cap.
_FOLD_NONASCII = {}   # answers of `_folds_to_ascii`, kept for the process (bounded, see below)


def _folds_to_ascii(char):
    """True for a character the engine itself reads as ASCII before it matches: the look alike
    map and compatibility folding. Decoding such a character cannot show the engine anything it
    does not already read the same way from the raw text."""
    hit = _FOLD_NONASCII.get(char)
    if hit is None:
        hit = (char in HOMOGLYPHS) or unicodedata.normalize("NFKC", char).isascii()
        if len(_FOLD_NONASCII) < 4096:
            _FOLD_NONASCII[char] = hit
    return hit


def accept(decoded):
    """Whether a decoded run is text worth putting in the view.

    Printable only (a lone surrogate is not printable). Then one of:
    - every character is ASCII or one the engine folds to ASCII, at any length. English written in
      UTF-7 decodes to ASCII, and a lone look alike letter (`+BD4-` is Cyrillic o) is exactly how
      a sentence is split;
    - at least 8 characters with at least 60 percent letters or space: other scripts, long runs only,
      so a random base64 looking token is not taken for text.
    """
    if not decoded or not decoded.isprintable():
        return False
    if all(c.isascii() or _folds_to_ascii(c) for c in decoded):
        return True
    return len(decoded) >= 8 and sum(1 for c in decoded if c.isalpha() or c == " ") / len(decoded) >= 0.6


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
            try:
                decoded = codecs.decode(("+" + text[i + 1:end] + "-").encode("ascii"), "utf-7")
            except (UnicodeError, ValueError):
                decoded = None
            if decoded is not None and accept(decoded):
                out.append(text[last:i])
                out.append(decoded)
                last = stop
        i = text.find("+", stop)
    if not out:
        return None
    out.append(text[last:])
    return "".join(out)
