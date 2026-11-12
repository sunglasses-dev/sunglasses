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
import collections
import re
import unicodedata

from .preprocessor import HOMOGLYPHS

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
    """True for a character the engine itself reads as ASCII before it matches: the look alike
    map and compatibility folding. Decoding such a character cannot show the engine anything it
    does not already read the same way from the raw text."""
    hit = _FOLD_NONASCII.get(char)
    if hit is None:
        hit = (char in HOMOGLYPHS) or unicodedata.normalize("NFKC", char).isascii()
        if len(_FOLD_NONASCII) < 4096:
            _FOLD_NONASCII[char] = hit
    return hit


_DROPPED = frozenset(("Cs", "Cn", "Co"))                       # lone surrogate, unassigned, private use: no reading at all
_NEUTRAL = frozenset(("Cc", "Cf", "Zs", "Zl", "Zp"))           # controls, format characters, spaces: no letters, no objection


_KANA_HAN = ("CJK", "HIRAGANA", "KATAKANA")


def _script(char):
    """A coarse script key: the first word of the character name, with Han and kana as one script (Japanese)."""
    word = unicodedata.name(char, "?").split(" ", 1)[0]
    return "CJK" if word in _KANA_HAN else word


def read_run(decoded):
    """The text of one decoded run as it goes into the view, or None when the run is not text.

    Judged per character, never the whole run (C1191, T8 and T9 11:45): a newline, a tab, a zero width
    joiner or a no break space inside a run used to make the whole run "not printable" and hide a full
    sentence a model still reads. A character with no reading (lone surrogate, unassigned, private use) is
    dropped, and what is left is kept. Then one of:
    - every character is ASCII, a control, format or space character, or one the engine folds to ASCII
      (the look alike map, or NFKC giving ASCII), at any length. English written in UTF-7 decodes to ASCII,
      and a lone look alike letter (`+BD4-` is Cyrillic o) is exactly how a sentence is split;
    - at least 8 characters, at least 60 percent of the decode letters, controls or spaces, and at least 80 percent
      of the non-ASCII ones in one script, and at most 20 percent of the decode dropped: other scripts, long runs only, so a random base64 looking token is not
      taken for text.
    Nothing left after the drop is not text.
    """
    if not decoded:
        return None
    if decoded.isascii():
        return decoded
    text = "".join(c for c in decoded if unicodedata.category(c) not in _DROPPED)
    if not text:
        return None
    if all(c.isascii() or unicodedata.category(c) in _NEUTRAL or _folds_to_ascii(c) for c in text):
        return text
    # Other scripts, long runs only. Random base64 looking text decodes to units spread over the whole plane
    # (CJK, Hangul, Yi, private use, unassigned), and most of those are letters, so "mostly letters" alone
    # cannot tell it from text. Real text in another script stays in one script, so that is required too.
    # The share of letters is taken over what was DECODED, so characters dropped above count against the run.
    if len(text) < 8 or len(text) < 0.8 * len(decoded):    # real text has no characters without a reading
        return None
    if sum(1 for c in text if c.isalpha() or unicodedata.category(c) in _NEUTRAL) / len(decoded) < 0.6:
        return None
    scripts = collections.Counter(_script(c) for c in text if not c.isascii() and unicodedata.category(c) not in _NEUTRAL)
    if scripts and max(scripts.values()) / sum(scripts.values()) >= 0.8:
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
            # everything before it (T9 11:46). A shorter body is decoded strictly: measured on 300 commit diffs, an
            # identifier after a plus (`+ALL_FIRES`) is a 3 to 5 letter body whose leftover bits are not zero, and
            # with "ignore" 17 of them built a view for no reason. A short run with a stray letter is a known gap.
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
