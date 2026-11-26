"""The words of the page for a finding, so a report quotes what the person wrote.

The scanner matches on a folded copy of the input: lowercase, look-alike letters and leet digits mapped,
blanks collapsed, hidden characters dropped. `matched_text` is a cut of that copy, so on a report it can read
"gls-pi-ooi" for GLS-PI-001, start in the middle of a word, or be empty (a rule built from lookaheads consumes
nothing). `shown_text(raw, folded)` finds the first span of the input that folds to `folded`, widens it to whole
words, joins its blanks, and cuts a long one at a space. It reads only the first READ_CAP characters of the input.

It is made when a report is drawn, never while a scan runs (finding dicts do not carry it), and the scanner's
`matched_text` is not changed by it. When the words are not in the input as written (a decoded or reversed view),
the folded words are shown as they are. An empty match shows NO_SINGLE_PHRASE.

The worker keeps the same function in JavaScript (src/shown_text.js); tests/fixtures/shown_text_rows.json holds the
rows both sides must agree on.
"""
import re
import unicodedata

from .preprocessor import HOMOGLYPHS, INVISIBLE_CHARS, LEET

NO_SINGLE_PHRASE = "no single phrase: this rule reads the whole text"
READ_CAP = 200_000
SHOW_MAX = 120
_BLANKS = re.compile(r"[ \t\r\n\f\v]+")

_INVERSE = {}
for _table in (HOMOGLYPHS, LEET):
    for _src, _dst in _table.items():
        if len(_dst) == 1:
            _INVERSE.setdefault(_dst, []).append(_src)
_HIDDEN = INVISIBLE_CHARS.pattern
_CLASSES = {}


def _char(c):
    """A pattern for the input characters that fold to c."""
    got = _CLASSES.get(c)
    if got is None:
        alts = {c}
        up = c.upper()
        if len(up) == 1:
            alts.add(up)
        alts.update(_INVERSE.get(c, ()))
        got = _CLASSES[c] = "(?:" + "|".join(re.escape(a) for a in sorted(alts)) + ")"
    return got


_EXPANDED = None


def _expanded():
    """Folded words that one input character becomes (an ellipsis becomes three dots, a ligature two letters)."""
    global _EXPANDED
    if _EXPANDED is None:
        table = {}
        for cp in range(0xA0, 0x10000):
            if 0xD800 <= cp < 0xE000:
                continue
            c = chr(cp)
            e = unicodedata.normalize("NFKC", c).lower()
            if 1 < len(e) <= 4 and not e.isspace():
                table.setdefault(e, []).append(c)
        _EXPANDED = table
    return _EXPANDED


def _pattern(folded):
    parts, last_blank = [], True
    table = _expanded()
    i = 0
    while i < len(folded):
        c = folded[i]
        if c.isspace():
            if not last_blank:
                parts.append("(?:\\s|" + _HIDDEN + ")+")
            last_blank = True
            i += 1
            continue
        if parts and not last_blank:
            parts.append("(?:" + _HIDDEN + ")*")
        step = 1
        for size in (4, 3, 2):
            raws = table.get(folded[i:i + size])
            if raws and len(folded[i:i + size]) == size:
                spelled = "(?:" + _HIDDEN + ")*"
                parts.append("(?:" + "|".join(re.escape(r) for r in sorted(raws)) + "|"
                             + spelled.join(_char(x) for x in folded[i:i + size]) + ")")
                step = size
                break
        else:
            parts.append(_char(c))
        last_blank = False
        i += step
    while parts and parts[-1].startswith("(?:\\s|"):
        parts.pop()
    return "".join(parts)


def _cut(text):
    text = _BLANKS.sub(" ", text).strip()
    if len(text) > SHOW_MAX:
        text = text[:SHOW_MAX]
        at = text.rfind(" ")
        text = (text[:at] if at > 0 else text).rstrip() + " …"
    return text


def shown_text(raw, folded):
    """The page words for one finding; see the module note."""
    if not folded or not folded.strip():
        return NO_SINGLE_PHRASE
    page = raw[:READ_CAP] if raw else ""
    pattern = _pattern(folded)
    hit = re.search(pattern, page) if pattern else None
    if not hit:
        return _cut(folded)
    start, end = hit.start(), hit.end()
    while start > 0 and page[start - 1].isalnum() and page[start].isalnum():
        start -= 1
    while end < len(page) and page[end - 1].isalnum() and page[end].isalnum():
        end += 1
    return _cut(page[start:end])
