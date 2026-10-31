"""
SUNGLASSES Preprocessor — Normalizes text before pattern matching.

Strips Unicode tricks, decodes Base64/URL/HTML/hex/ROT13, collapses
invisible characters, maps homoglyphs to ASCII. Defends against 17+
known evasion techniques used to bypass prompt injection scanners.
"""

import base64
import codecs
import html
import re
import unicodedata
from urllib.parse import unquote


# Punctuation that looks like an ASCII sign and that NFKC does not map. Read by
# the regex lane's folded view only (replace_lookalikes below); HOMOGLYPHS, and
# with it the keyword lane, is left as it was. Every entry is one code point to
# one code point. Kept small on purpose: only
# signs drawn like the ASCII one. The en dash, em dash and box-drawing lines are
# not here: they are drawn visibly longer or heavier and are everywhere in
# ordinary prose and directory trees, so mapping them would fold almost every
# document for no reach.
PUNCT_LOOKALIKES = {
    '\u2010': '-', '\u2011': '-', '\u2012': '-',   # hyphen, non-breaking hyphen, figure dash
    '\u2043': '-', '\u2212': '-', '\u02d7': '-',   # hyphen bullet, minus sign, modifier minus
    '\u00a6': '|', '\u2758': '|', '\u2223': '|',   # broken bar, light vertical bar, divides
    '\u01c0': '|', '\u23d0': '|',                  # dental click, vertical line extension
    '\u2215': '/', '\u2044': '/', '\u29f8': '/',   # division slash, fraction slash, big solidus
    '\ua789': ':', '\u02f8': ':', '\u2236': ':',   # modifier letter colons, ratio
}

# Homoglyph map: visually similar Unicode chars → ASCII equivalents
# Attackers use Cyrillic/Greek lookalikes to bypass keyword filters
HOMOGLYPHS = {
    '\u0410': 'A', '\u0412': 'B', '\u0421': 'C', '\u0415': 'E',
    '\u041d': 'H', '\u041a': 'K', '\u041c': 'M', '\u041e': 'O',
    '\u0420': 'P', '\u0422': 'T', '\u0425': 'X',
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
    # Ukrainian Cyrillic (added apr11 after baseline miss)
    '\u0406': 'I', '\u0456': 'i',    # Ukrainian І / і — the big miss
    '\u0407': 'I', '\u0457': 'i',    # Ї / ї
    '\u0404': 'E', '\u0454': 'e',    # Є / є
    '\u0490': 'G', '\u0491': 'g',    # Ґ / ґ
    # Armenian lookalikes
    '\u0548': 'O', '\u054d': 'S',
    # Georgian / Ethiopic edge cases
    '\u10e5': 'K',
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H',
    '\u0399': 'I', '\u039a': 'K', '\u039c': 'M', '\u039d': 'N',
    '\u039f': 'O', '\u03a1': 'P', '\u03a4': 'T', '\u03a7': 'X',
    '\u0396': 'Z',
    '\u03b1': 'a', '\u03b5': 'e', '\u03bf': 'o', '\u03c1': 'p',
    '\u03c5': 'u',
    # Fullwidth Latin
    '\uff21': 'A', '\uff22': 'B', '\uff23': 'C', '\uff24': 'D',
    '\uff25': 'E', '\uff26': 'F', '\uff27': 'G', '\uff28': 'H',
    '\uff29': 'I', '\uff2a': 'J', '\uff2b': 'K', '\uff2c': 'L',
    '\uff2d': 'M', '\uff2e': 'N', '\uff2f': 'O', '\uff30': 'P',
    '\uff31': 'Q', '\uff32': 'R', '\uff33': 'S', '\uff34': 'T',
    '\uff35': 'U', '\uff36': 'V', '\uff37': 'W', '\uff38': 'X',
    '\uff39': 'Y', '\uff3a': 'Z',
    '\uff41': 'a', '\uff42': 'b', '\uff43': 'c', '\uff44': 'd',
    '\uff45': 'e', '\uff46': 'f', '\uff47': 'g', '\uff48': 'h',
    '\uff49': 'i', '\uff4a': 'j', '\uff4b': 'k', '\uff4c': 'l',
    '\uff4d': 'm', '\uff4e': 'n', '\uff4f': 'o', '\uff50': 'p',
    '\uff51': 'q', '\uff52': 'r', '\uff53': 's', '\uff54': 't',
    '\uff55': 'u', '\uff56': 'v', '\uff57': 'w', '\uff58': 'x',
    '\uff59': 'y', '\uff5a': 'z',
}

# Leetspeak map
LEET = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '@': 'a', '$': 's', '!': 'i',
}

# Control characters that are neither whitespace nor escape. A NUL between
# letters (or after each ASCII letter of a UTF-16 file saved without a byte
# order mark) split a phrase for every lane. Tab, newline, carriage return,
# vertical tab, form feed, the four separators and next line stay because \s
# reads them as spaces, and escape stays because a rule matches it raw.
CONTROL_RANGES = '\x00-\x08\x0e-\x1a\x7f-\x84\x86-\x9f'
CONTROL_CHARS = re.compile('[' + CONTROL_RANGES + ']')
_CONTROL_RUN = re.compile('[' + CONTROL_RANGES + ']+')


def controls_as_spaces(text: str) -> str:
    """The text with each run of control characters read as one space, except where the run
    already stands next to blank space or at an edge of the text: deleting it there leaves
    the same words as reading it as a space, and the extra space would only double a blank
    that the normalizer collapses again."""
    def one(run):
        a, b = run.start(), run.end()
        if a == 0 or b == len(text) or text[a - 1].isspace() or text[b].isspace():
            return ""
        return " "
    return _CONTROL_RUN.sub(one, text)

# Zero-width and invisible Unicode characters
INVISIBLE_CHARS = re.compile(
    '[\u200b\u200c\u200d\u200e\u200f'   # zero-width spaces/joiners
    '\u2060\u2061\u2062\u2063\u2064'     # word joiner, invisible operators
    '\ufeff'                              # BOM / zero-width no-break space
    '\u00ad'                              # soft hyphen
    '\u034f'                              # combining grapheme joiner
    '\u061c'                              # Arabic letter mark
    '\u2028\u2029'                        # line/paragraph separators
    '\U000e0001-\U000e007f'              # Unicode tag characters
    + CONTROL_RANGES +
    ']'
)

# Enclosed alphanumerics (circled letters etc.)
ENCLOSED_ALPHA = re.compile(r'[\u24b6-\u24e9\u2460-\u2473\u24ea-\u24ff]')


# Separates the enrichment views (plain / ROT13 / reversed / shape) inside the
# normalized string. Excerpts shown to humans are clamped at this boundary so a
# matched_text window can never splice decoded gibberish onto plain text
# (0.4.3). Stripped from raw input first so an attacker cannot plant it.
VIEW_SEP = "\x1e"

# The ROT13 / reversed / shape views are built only when the folded plain text
# is at most this long. The engine's step 3.5 reads the same number through
# normalize_with_length(), so the two gates measure one string, not two.
ENRICH_MAX_LEN = 2000


def normalize(text: str) -> str:
    """Full normalization pipeline. Returns cleaned text for pattern matching."""
    return normalize_with_length(text)[0]


def normalize_with_length(text: str, record=None) -> tuple:
    """normalize(), plus the length of the folded plain text that the
    enrichment gate measured. That length is taken after every fold and before
    any view is appended, so a caller gating on it agrees with this function
    about what counts as a short input.

    record, when given, is a list: each base64 blob the pipeline replaced is
    appended to it, in the plain view and in the shadow view's own pipeline, and
    so is HTML_FALLBACK each time the entity step gave up on the whole input. It
    changes nothing else; a caller that needs to know whether the pipeline
    decoded anything asks the pipeline and does not run a second decoder."""
    text = text.replace(VIEW_SEP, " ")
    # Read before strip_invisible removes them, so the plain view still loses
    # them (a split phrase keeps matching) and the shadow view sees the text.
    shadow = decode_shadow_ascii(text)
    # Control characters are deleted below so a phrase they split reads whole.
    # Deleting one also joins what it separated, and a base64 run that followed
    # a NUL then merges with the word before it and no longer decodes. So the
    # same text with each control read as a space is kept as a view of its own,
    # behind the separator, and decoded on its original boundaries.
    spaced = controls_as_spaces(text) if CONTROL_CHARS.search(text) else None
    if spaced is not None and spaced == CONTROL_CHARS.sub("", text):
        # Every control stands next to blank space: the view would repeat the plain one.
        spaced = None
    text = strip_invisible(text)
    text = normalize_unicode(text)
    text = replace_homoglyphs(text)
    # Iteratively unwrap LAYERED encodings — base64(base64(...)), base64(hex(...)),
    # url(base64(...)) etc. Attackers nest encoders so a single decode pass leaves
    # a still-encoded payload the matcher can't see. Loop until the text stops
    # changing, capped at DECODE_MAX_PASSES so it stays bounded; clean text breaks
    # after one pass (nothing decodes → no change), so this adds no cost to the
    # common case. Base64 decode stays BEFORE leetspeak (leet corrupts b64).
    DECODE_MAX_PASSES = 3
    for _ in range(DECODE_MAX_PASSES):
        before = text
        text = decode_html_entities(text, record)     # HTML entities (&#73; etc) → chars
        text = decode_url_encoding(text)      # URL encoding (%49 etc) → chars
        text = decode_hex_escapes(text)       # \x49 etc → chars
        text = decode_base64_segments(text, record)   # base64 blobs → decoded text
        if text == before:
            break
    text = decode_leetspeak(text)
    text = strip_delimiter_padding(text)  # Collapse spaced chars BEFORE whitespace collapse
    text = collapse_whitespace(text)
    # ── Obfuscation enrichment (ROT13 / reversed / shape-confusion) ──────────
    # These three views catch payloads that are LITERALLY ROT13-encoded,
    # reversed, or use lowercase-l-for-capital-I. Those evasions only ever
    # appear in SHORT crafted injection strings — never in whole documents.
    # Applying them to large inputs was actively harmful (Jun 9 2026):
    #   1. it gave almost no real recall (a clean README/source file is not
    #      ROT13 ciphertext), but
    #   2. the reversed/scrambled copy of a big document triggered pathological
    #      regex backtracking that hung a single scan for 70+ seconds on normal
    #      Python stdlib code — a real performance / denial-of-service bug, and
    #   3. it added a few extra false positives on the scrambled text.
    # So enrich ONLY short inputs, where these evasions actually occur; larger
    # inputs (files, web pages, tool outputs) skip enrichment entirely.
    folded_length = len(text)
    if folded_length <= ENRICH_MAX_LEN:
        # ROT13 enrichment so "Vtaber cerivbhf vafgehpgvbaf" also sees
        # "ignore previous instructions"
        rot = decode_rot13(text)
        if rot != text:
            text = text + " " + VIEW_SEP + " " + rot
        # Reverse enrichment for reversed-string attacks
        text = text + " " + VIEW_SEP + " " + text[::-1]
        text = text.lower()
        # Shape-confusion: standalone 'l' at word boundary → 'i' (covers
        # "lgnore all prevIous Instructions" where lowercase L stands in for I)
        shape_variant = re.sub(r'\bl(?=[a-z])', 'i', text)
        if shape_variant != text:
            text = text + " " + VIEW_SEP + " " + shape_variant
    else:
        # Long inputs: the REVERSE/shape enrichment historically caused
        # pathological regex backtracking on big documents (Jun-9 2026 ReDoS), so
        # those stay OFF here. ROT13 enrichment is safe and cheap though — it
        # feeds only the linear keyword lane (the regex lane matches on RAW text,
        # not this normalized copy), so a ROT13-encoded payload buried in a long
        # document is still caught. Measured cost: ~tens of ms on a 200KB doc.
        rot = decode_rot13(text)
        if rot != text:
            text = text + " " + VIEW_SEP + " " + rot
        text = text.lower()
    if spaced is not None:
        text = text + " " + VIEW_SEP + " " + normalize(spaced)
    if shadow is not None:
        # Its own views, behind the separator, so an excerpt never joins it
        # to the plain text.
        text = text + " " + VIEW_SEP + " " + normalize_with_length(shadow, record)[0]
    return text, folded_length


# Invisible code points that shadow printable ASCII one for one.
SHADOW_ASCII = re.compile('[\U000e0020-\U000e007e]')


def decode_shadow_ascii(text: str):
    """The input with each shadow code point read as the ASCII it shadows.

    None when there is none, so ordinary text gains no extra view.
    """
    if not SHADOW_ASCII.search(text):
        return None
    return SHADOW_ASCII.sub(lambda m: chr(ord(m.group()) - 0xE0000), text)


def strip_invisible(text: str) -> str:
    """Remove zero-width and invisible Unicode characters."""
    return INVISIBLE_CHARS.sub('', text)


def normalize_unicode(text: str) -> str:
    """NFKC normalization — collapses fullwidth, compatibility forms."""
    return unicodedata.normalize('NFKC', text)


def replace_homoglyphs(text: str) -> str:
    """Replace visually similar Unicode chars with ASCII equivalents."""
    return ''.join(HOMOGLYPHS.get(c, c) for c in text)


# ── The regex lane's folded view ────────────────────────────────────────────
# The engine's regex lane reads the raw text first and, for non-ASCII input,
# a folded copy of it (engine scan, step 3). The helpers below build that copy.
# They do not feed normalize(): the keyword lane's view still deletes only
# INVISIBLE_CHARS and maps only HOMOGLYPHS. The engine keeps the #342 fold as
# its own subject too, so this copy only adds subjects to what a rule reads.

# Every code point that renders as nothing, written out as ranges so the set is
# the same on every Python the package supports (unicodedata's tables differ
# between interpreter versions). It is the Unicode Default_Ignorable_Code_Point
# property (DerivedCoreProperties.txt), which includes every format character
# (category Cf) that has no visible glyph, plus the three Cf characters it
# leaves out but that renderers do not draw either (interlinear annotation
# U+FFF9-FFFB, Egyptian hieroglyph format controls U+13430-1343F), plus
# INVISIBLE_CHARS above. Left out on purpose: the Cf characters that DO render
# (Arabic number signs U+0600-0605, U+06DD, U+070F, U+0890-0891, U+08E2,
# U+110BD, U+110CD), and unassigned code points outside the ranges the standard
# reserves as ignorable: those render as a visible box, and which code points
# are unassigned depends on the interpreter's Unicode version.
IGNORABLE_RANGES = (
    (0x0000, 0x0008),    # C0 controls, CONTROL_RANGES (INVISIBLE_CHARS)
    (0x000E, 0x001A),
    (0x007F, 0x0084),    # delete, C1 controls (next line U+0085 stays)
    (0x0086, 0x009F),
    (0x00AD, 0x00AD),    # soft hyphen
    (0x034F, 0x034F),    # combining grapheme joiner
    (0x061C, 0x061C),    # Arabic letter mark
    (0x115F, 0x1160),    # Hangul choseong / jungseong fillers
    (0x17B4, 0x17B5),    # Khmer inherent vowels
    (0x180B, 0x180F),    # Mongolian variation selectors, vowel separator
    (0x200B, 0x200F),    # zero-width space / joiners, LRM / RLM
    (0x2028, 0x2029),    # line / paragraph separator (INVISIBLE_CHARS)
    (0x202A, 0x202E),    # bidi embeddings and overrides
    (0x2060, 0x206F),    # word joiner, invisible operators, bidi isolates, deprecated
    (0x3164, 0x3164),    # Hangul filler
    (0xFE00, 0xFE0F),    # variation selectors
    (0xFEFF, 0xFEFF),    # BOM / zero-width no-break space
    (0xFFA0, 0xFFA0),    # halfwidth Hangul filler
    (0xFFF0, 0xFFFB),    # reserved ignorable, interlinear annotation
    (0x13430, 0x1343F),  # Egyptian hieroglyph format controls
    (0x1BCA0, 0x1BCA3),  # shorthand format controls
    (0x1D173, 0x1D17A),  # musical symbol format controls
    (0xE0000, 0xE0FFF),  # tag characters, variation selectors supplement, reserved
)

_IGNORABLE_CLASS = "".join(
    re.escape(chr(lo)) if lo == hi else f"{re.escape(chr(lo))}-{re.escape(chr(hi))}"
    for lo, hi in IGNORABLE_RANGES)
IGNORABLE_CHARS = re.compile(f"[{_IGNORABLE_CLASS}]+")

# Characters that are not whitespace to a regex but are drawn as a blank.
BLANKS = {'\u2800': ' '}   # Braille pattern blank

# One translation table: HOMOGLYPHS (look-alike letters), the punctuation
# look-alikes and the blanks. Every entry maps one code point to one code point, so the fold
# never grows.
_LOOKALIKE_TABLE = str.maketrans({**HOMOGLYPHS, **PUNCT_LOOKALIKES, **BLANKS})

# An ignorable run with a letter or digit on both sides: where the fold that
# deletes it would glue two words ("ignore" + U+200B + "all" -> "ignoreall").
# A letter is ASCII or one the homoglyph table maps to ASCII.
_WORD_CHAR = "A-Za-z0-9" + "".join(re.escape(c) for c, a in HOMOGLYPHS.items() if a.isalnum())
_IGNORABLE_BETWEEN_WORDS = re.compile(
    f"(?<=[{_WORD_CHAR}])[{_IGNORABLE_CLASS}]+(?=[{_WORD_CHAR}])")
WORD_CHAR = re.compile(f"[{_WORD_CHAR}]")

# A numeric character reference that spells an ASCII letter or digit. Markup
# escapes (&lt; &#60; &#39; ...) are left alone on purpose: decoding them would
# turn every escaped code sample in a web page into live markup.
_LETTER_REFERENCE = re.compile(r"&#(?:[xX]0*([0-9A-Fa-f]{1,6})|0*([0-9]{1,7}));?")
_REFERENCE_TAIL = frozenset("0123456789abcdefABCDEFxX;")


def _letter_reference(match):
    value = int(match.group(1), 16) if match.group(1) else int(match.group(2))
    if value < 128 and chr(value).isalnum():
        return chr(value)
    return match.group(0)


def decoded_before(text: str, pos: int) -> str:
    """The character that decode_letter_references(text) holds just before what
    text[pos] becomes, or "" at the start."""
    k = pos
    while k > 0 and text[k - 1] in _REFERENCE_TAIL:
        k -= 1
    if k >= 2 and text.startswith("&#", k - 2):
        match = _LETTER_REFERENCE.match(text, k - 2)
        if match and match.end() == pos:
            return _letter_reference(match)[-1]
    return text[pos - 1] if pos else ""


def decoded_at(text: str, pos: int) -> str:
    """The first character that decode_letter_references makes of text[pos:], or ""
    at the end. Only right for a position no reference reaches over, such as the
    end of an ignorable run."""
    if text.startswith("&#", pos):
        match = _LETTER_REFERENCE.match(text, pos)
        if match:
            return _letter_reference(match)[0]
    return text[pos] if pos < len(text) else ""


def decode_letter_references(text: str) -> str:
    """Decode the numeric character references that spell ASCII letters or digits
    (&#105; &#x69; -> i). Anything else, markup escapes included, is kept."""
    if "&#" not in text:
        return text
    return _LETTER_REFERENCE.sub(_letter_reference, text)


# An ignorable run between two Braille cells. Braille words are written cell
# after cell, and a blank-drawn filler (U+3164) is a word gap there; deleting it
# would join two short words into one long cell run, which the Braille encoding
# rule reads as hidden text. Such a run is read as the space it is drawn as.
_IGNORABLE_BETWEEN_BRAILLE = re.compile(f"(?<=[\u2800-\u28ff])[{_IGNORABLE_CLASS}]+(?=[\u2800-\u28ff])")


def strip_ignorable(text: str) -> str:
    """Delete every code point that renders as nothing (IGNORABLE_RANGES), except
    that a run of them between two Braille cells is read as one space."""
    return IGNORABLE_CHARS.sub("", _IGNORABLE_BETWEEN_BRAILLE.sub(" ", text))


def space_ignorable_between_words(text: str):
    """The text with each ignorable run that sits between two letters or digits
    read as one space. None when there is no such run."""
    spaced, count = _IGNORABLE_BETWEEN_WORDS.subn(" ", text)
    return spaced if count else None


def replace_lookalikes(text: str) -> str:
    """Homoglyph letters, punctuation look-alikes and blanks to their ASCII
    character; one code point to one code point."""
    return text.translate(_LOOKALIKE_TABLE)


def decode_leetspeak(text: str) -> str:
    """Convert common leetspeak substitutions back to letters."""
    return ''.join(LEET.get(c, c) for c in text)


def collapse_whitespace(text: str) -> str:
    """Collapse multiple spaces, tabs, unusual whitespace to single space."""
    text = re.sub(r'[\t\r\x0b\x0c]+', ' ', text)
    text = re.sub(r' {2,}', ' ', text)
    return text.strip()


# Put in a record by decode_html_entities when it gave up on the whole input. It is the one step of
# the pipeline whose result for a stretch of text depends on the text around it.
HTML_FALLBACK = "\x00html-whole-input-fallback"


def decode_html_entities(text: str, record=None) -> str:
    """Decode HTML entities (&#73; &amp; &lt; etc) to raw characters.

    record, when given, is a list that HTML_FALLBACK is appended to when the whole input is left
    unchanged because one reference in it could not be read."""
    if '&' not in text:
        return text
    try:
        return html.unescape(text)
    except Exception:
        if record is not None:
            record.append(HTML_FALLBACK)
        return text


def decode_url_encoding(text: str) -> str:
    """Decode URL percent-encoding (%49 → I etc). Only runs if % is present."""
    if '%' not in text:
        return text
    # Only decode if there's a plausible percent-encoded sequence
    if not re.search(r'%[0-9A-Fa-f]{2}', text):
        return text
    try:
        return unquote(text)
    except Exception:
        return text


def decode_hex_escapes(text: str) -> str:
    """Decode \\xNN hex escape sequences (\\x49 → I)."""
    if '\\x' not in text:
        return text
    def _hex_sub(match):
        try:
            return chr(int(match.group(1), 16))
        except Exception:
            return match.group(0)
    return re.sub(r'\\x([0-9A-Fa-f]{2})', _hex_sub, text)


def decode_rot13(text: str) -> str:
    """Return ROT13-decoded version of text. Used for enrichment, not replacement."""
    try:
        return codecs.decode(text, 'rot_13')
    except Exception:
        return text


def decode_base64_segments(text: str, record=None) -> str:
    """Find and inline-decode Base64 segments, REPLACING the encoded text with decoded.

    record, when given, is a list that each replaced segment is appended to."""
    def _try_decode(match):
        segment = match.group(0)
        try:
            decoded = base64.b64decode(segment).decode('utf-8', errors='ignore')
            if decoded.isprintable() and len(decoded) > 4:
                if record is not None:
                    record.append(segment)
                return decoded  # Replace encoded with decoded for pattern matching
        except Exception:
            pass
        return segment

    return re.sub(r'[A-Za-z0-9+/]{20,}={0,2}', _try_decode, text)


def strip_delimiter_padding(text: str) -> str:
    """Remove delimiter-based evasion (d.e.l.i.m.i.t.e.d or d-e-l-i-m or s p a c e d).

    Both collapse rules bottom out at THREE letters. They used to require 5
    (dotted) / 4 (spaced), which left a hole: an attacker only had to split one
    short word to break the phrase. "ignore a l l previous instructions"
    normalized to "ignore a l l previous instructions" — the long words
    collapsed, "a l l" survived, and no keyword phrase matched. Three is the
    floor because a 2-letter group ("e.g", "P S", "U S") is overwhelmingly
    ordinary prose, not evasion.
    """
    # Single char separated by dots, dashes, or underscores (3+ letters)
    text = re.sub(
        r'\b([a-zA-Z])[.\-_]([a-zA-Z])([.\-_][a-zA-Z])+\b',
        lambda m: m.group(0).replace('.', '').replace('-', '').replace('_', ''),
        text
    )
    # Single char separated by spaces: "i g n o r e" → "ignore"
    # Also handles double-spaced: "i  g  n  o  r  e"
    def _collapse_spaced_word(m):
        """Collapse single-spaced letters into a word: 'i g n o r e' → 'ignore'"""
        return m.group(0).replace(' ', '')

    # Process word-by-word: split on 2+ spaces (word boundaries), collapse each word
    parts = re.split(r'(\s{2,})', text)
    collapsed_parts = []
    for part in parts:
        if re.match(r'\s+$', part):
            collapsed_parts.append(' ')  # Preserve word boundary as single space
        else:
            # Collapse "i g n o r e" within each word-group
            collapsed = re.sub(
                r'(?<!\w)([a-zA-Z] ){2,}[a-zA-Z](?!\w)',
                _collapse_spaced_word,
                part
            )
            collapsed_parts.append(collapsed)
    text = ''.join(collapsed_parts)
    return text


# Every way of writing text that the scanner reads back before it matches, one
# row per thing undone, so a public count of "normalization techniques" is
# len(NORMALIZATION_STEPS) and not a number typed by hand. A row names
# the functions that do it: the keyword lane's first, then the regex lane's
# wider version of the same undo. Two functions undoing one thing are one
# technique, not two. An empty tuple means the step is written inline in
# normalize_with_length. tests/test_normalization_steps.py proves each row on
# a crafted input and fails when either lane calls a function no row names;
# tools/gen_normalization_stats.py writes the count into stats/current.json.
NORMALIZATION_STEPS = (
    # (step, what it undoes, functions)
    ("shadow_ascii", "printable ASCII written as invisible Unicode tag characters",
     ("decode_shadow_ascii",)),
    ("hidden_separators", "a control or invisible character used as the space between two words",
     ("controls_as_spaces", "space_ignorable_between_words")),
    ("invisible_characters", "zero-width, bidi, control and other invisible characters inside a word",
     ("strip_invisible", "strip_ignorable")),
    ("compatibility_forms", "fullwidth, circled, mathematical and other compatibility forms (NFKC)",
     ("normalize_unicode",)),
    ("homoglyphs", "letters from another script that look like Latin ones",
     ("replace_homoglyphs", "replace_lookalikes")),
    ("html_references", "HTML character references such as &#105;",
     ("decode_html_entities", "decode_letter_references")),
    ("url_encoding", "URL percent-encoding such as %69", ("decode_url_encoding",)),
    ("hex_escapes", "hex escapes such as \\x69", ("decode_hex_escapes",)),
    ("base64", "base64 blobs, up to three nested layers with the decoders above",
     ("decode_base64_segments",)),
    ("leetspeak", "digits and symbols standing in for letters, such as 1gn0r3", ("decode_leetspeak",)),
    ("delimiter_padding", "letters split by dots, dashes or single spaces, such as i.g.n.o.r.e",
     ("strip_delimiter_padding",)),
    ("whitespace_runs", "tabs and runs of spaces between words", ("collapse_whitespace",)),
    ("rot13", "ROT13, read as an extra view", ("decode_rot13",)),
    ("reversed", "text written backwards, read as an extra view of short inputs", ()),
    ("mixed_case", "mixed upper and lower case", ()),
    ("l_for_i", "a lowercase l written for a capital I, read as an extra view of short inputs", ()),
)
