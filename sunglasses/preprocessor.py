"""
GLASSES Preprocessor — Normalizes text before pattern matching.

Strips Unicode tricks, decodes Base64, collapses invisible characters,
maps homoglyphs to ASCII. This alone defends against 12 known evasion
techniques used to bypass prompt injection scanners.
"""

import base64
import re
import unicodedata


# Homoglyph map: visually similar Unicode chars → ASCII equivalents
# Attackers use Cyrillic/Greek lookalikes to bypass keyword filters
HOMOGLYPHS = {
    '\u0410': 'A', '\u0412': 'B', '\u0421': 'C', '\u0415': 'E',
    '\u041d': 'H', '\u041a': 'K', '\u041c': 'M', '\u041e': 'O',
    '\u0420': 'P', '\u0422': 'T', '\u0425': 'X',
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
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
    ']'
)

# Enclosed alphanumerics (circled letters etc.)
ENCLOSED_ALPHA = re.compile(r'[\u24b6-\u24e9\u2460-\u2473\u24ea-\u24ff]')


def normalize(text: str) -> str:
    """Full normalization pipeline. Returns cleaned text for pattern matching."""
    text = strip_invisible(text)
    text = normalize_unicode(text)
    text = replace_homoglyphs(text)
    text = decode_base64_segments(text)   # Decode BEFORE leetspeak (leet corrupts b64)
    text = decode_leetspeak(text)
    text = strip_delimiter_padding(text)  # Collapse spaced chars BEFORE whitespace collapse
    text = collapse_whitespace(text)
    return text.lower()


def strip_invisible(text: str) -> str:
    """Remove zero-width and invisible Unicode characters."""
    return INVISIBLE_CHARS.sub('', text)


def normalize_unicode(text: str) -> str:
    """NFKC normalization — collapses fullwidth, compatibility forms."""
    return unicodedata.normalize('NFKC', text)


def replace_homoglyphs(text: str) -> str:
    """Replace visually similar Unicode chars with ASCII equivalents."""
    return ''.join(HOMOGLYPHS.get(c, c) for c in text)


def decode_leetspeak(text: str) -> str:
    """Convert common leetspeak substitutions back to letters."""
    return ''.join(LEET.get(c, c) for c in text)


def collapse_whitespace(text: str) -> str:
    """Collapse multiple spaces, tabs, unusual whitespace to single space."""
    text = re.sub(r'[\t\r\x0b\x0c]+', ' ', text)
    text = re.sub(r' {2,}', ' ', text)
    return text.strip()


def decode_base64_segments(text: str) -> str:
    """Find and inline-decode Base64 segments, REPLACING the encoded text with decoded."""
    def _try_decode(match):
        segment = match.group(0)
        try:
            decoded = base64.b64decode(segment).decode('utf-8', errors='ignore')
            if decoded.isprintable() and len(decoded) > 4:
                return decoded  # Replace encoded with decoded for pattern matching
        except Exception:
            pass
        return segment

    return re.sub(r'[A-Za-z0-9+/]{20,}={0,2}', _try_decode, text)


def strip_delimiter_padding(text: str) -> str:
    """Remove delimiter-based evasion (d.e.l.i.m.i.t.e.d or d-e-l-i-m or s p a c e d)."""
    # Single char separated by dots, dashes, or underscores
    text = re.sub(
        r'\b([a-zA-Z])[.\-_]([a-zA-Z])[.\-_]([a-zA-Z])([.\-_][a-zA-Z]){2,}\b',
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
                r'(?<!\w)([a-zA-Z] ){3,}[a-zA-Z](?!\w)',
                _collapse_spaced_word,
                part
            )
            collapsed_parts.append(collapsed)
    text = ''.join(collapsed_parts)
    return text
