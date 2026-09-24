"""GLS-SD-010-EMB r10 — the escape grammar as a TABLE, and the matrix built from it.

T9 RULING 13: stop adding escape cases one review at a time. Every escape a
JSON, Python or YAML 1.2 double-quoted string can spell is listed here with the
character it decodes to, each spelling is checked against the REAL decoder of
every grammar it is claimed for (json.loads, ast.literal_eval, yaml.safe_load),
and the expected verdict of every generated case comes from a reference rule
written here, independent of patterns.py.

THE PARITY CONTRACT. The rule reports iff EITHER reading of the bytes would
report under the literal-only rule:
  - the RAW reading: the text as it is;
  - the DECODED reading: the escape replaced by the character it decodes to.
The rule does not know which syntax it is reading, so a spelling that is an
escape in ANY of the three grammars counts as that escape everywhere
(syntax-blind). Example: `\\<SPACE>` is a YAML escape for a space, so
`"\\ API_KEY=` reads as an indented key even inside a Python string, where the
same bytes are a backslash and a space.

THE LITERAL-ONLY RULE (`literal_rule`): a boundary, then indentation, then a
key, then separator whitespace, then `=`.
  boundary     start of text, a line end (exactly the `str.splitlines` set, a
               test holds it there), or one of `" ' { [ ,`
  indentation  space or tab, any number
  key          one of KEYS, case-sensitive (the lowercase control)
  separator    any Python unicode whitespace (`\\s`), any number

R32 (the r10 NO GO). The table is what each grammar's reference LISTS. Two
families sit between listed escapes and only the decoders' own rules decide
them, so they are ENUMERATED from those rules and every spelling is handed to
the real decoders, which say what it decodes to (`DERIVED`, below). Nothing
in either family is a claim written here.
"""
from __future__ import annotations

import ast
import dataclasses
import json
import re
import string
import unicodedata
import warnings

import yaml

KEYS = ("API_KEY", "SECRET_KEY", "ACCESS_KEY", "TOKEN", "PASSWORD", "DATABASE_URL",
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY")
PW = "hunter" + "2"

LINE_ENDS = "\n\r\v\f\x1c\x1d\x1e\x85  "
DELIMS = "\"'{[,"
INDENT = " \t"
WHITESPACE = "".join(chr(c) for c in range(0x110000) if re.match(r"\s", chr(c)))

_LITERAL = re.compile(
    r"(?:\A|[" + re.escape(LINE_ENDS + DELIMS) + r"])[ \t]*(?:"
    + "|".join(sorted(KEYS, key=len, reverse=True)) + r")\s*=")


def literal_rule(text: str) -> bool:
    return bool(_LITERAL.search(text))


# ── the table ────────────────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True)
class Escape:
    spelling: str
    decoded: str            # "" for a line continuation
    grammars: frozenset     # of "json", "python", "yaml"


def _e(spelling, decoded, *grammars):
    return Escape(spelling, decoded, frozenset(grammars))


# One-character escapes, as each grammar's reference lists them.
ONE_CHAR = [
    # JSON (RFC 8259 §7)
    _e('\\"', '"', "json", "python", "yaml"),
    _e("\\\\", "\\", "json", "python", "yaml"),
    _e("\\/", "/", "json", "yaml"),
    _e("\\b", "\b", "json", "python", "yaml"),
    _e("\\f", "\f", "json", "python", "yaml"),
    _e("\\n", "\n", "json", "python", "yaml"),
    _e("\\r", "\r", "json", "python", "yaml"),
    _e("\\t", "\t", "json", "python", "yaml"),
    # Python (the reference's escape table)
    _e("\\'", "'", "python"),
    _e("\\a", "\a", "python", "yaml"),
    _e("\\v", "\v", "python", "yaml"),
    _e("\\\n", "", "python", "yaml"),        # line continuation / escaped break
    _e("\\\r", "", "python", "yaml"),
    _e("\\\r\n", "", "python", "yaml"),
    _e("\\\x85", "", "yaml"),                 # PyYAML breaks on these too
    _e("\\\u2028", "", "yaml"),
    _e("\\\u2029", "", "yaml"),
    # YAML 1.2 double-quoted (§5.7)
    _e("\\0", "\0", "python", "yaml"),       # Python reads it as octal
    _e("\\\t", "\t", "yaml"),
    _e("\\ ", " ", "yaml"),
    _e("\\e", "\x1b", "yaml"),
    _e("\\N", "\x85", "yaml"),
    _e("\\_", "\xa0", "yaml"),
    _e("\\L", " ", "yaml"),
    _e("\\P", " ", "yaml"),
]

# Bytes that look like an escape and are not one in any of the three: the
# decoded reading is the raw reading, so these are always allow controls.
NOT_ESCAPES = (["\\R", "\\V", "\\F", "\\T", "\\l", "\\p", "\\E", "\\q",
                "\\N{NOT A NAME}"]
               + ["\\" + c for c in WHITESPACE if c not in " \t\n\r\x85\u2028\u2029"])

# Python \N{...} names beyond unicodedata.name(): the formal aliases, and the
# names of the controls, which have no unicodedata.name(). Each is checked
# against ast.literal_eval by the self-check.
NAME_ALIASES = {
    0x09: ["CHARACTER TABULATION", "HORIZONTAL TABULATION", "TAB", "HT"],
    0x0A: ["LINE FEED", "NEW LINE", "END OF LINE", "LF", "NL", "EOL"],
    0x0B: ["LINE TABULATION", "VERTICAL TABULATION", "VT"],
    0x0C: ["FORM FEED", "FF"],
    0x0D: ["CARRIAGE RETURN", "CR"],
    0x1C: ["INFORMATION SEPARATOR FOUR", "FILE SEPARATOR", "FS"],
    0x1D: ["INFORMATION SEPARATOR THREE", "GROUP SEPARATOR", "GS"],
    0x1E: ["INFORMATION SEPARATOR TWO", "RECORD SEPARATOR", "RS"],
    0x1F: ["INFORMATION SEPARATOR ONE", "UNIT SEPARATOR", "US"],
    0x20: ["SP"],
    0x85: ["NEXT LINE", "NEL"],
    0xA0: ["NBSP"],
    0x202F: ["NNBSP"],
    0x205F: ["MMSP"],
}

# Every codepoint whose escaped spellings the matrix covers: everything the
# literal rule gives a meaning to, plus near neighbours that must stay allow.
CODEPOINTS = sorted({ord(c) for c in LINE_ENDS + DELIMS + INDENT + WHITESPACE + "="}
                    | {0x00, 0x07, 0x08, 0x1B, 0x2D, 0x2F, 0x3A, 0x41, 0x5C, 0x5D, 0x7D,
                       0x200B, 0xFEFF})


def _names(cp):
    names = list(NAME_ALIASES.get(cp, []))
    try:
        names.append(unicodedata.name(chr(cp)))
    except ValueError:
        pass
    return names


def _numeric(cp):
    out = []
    if cp < 0x100:
        for form in ("\\x%02x", "\\x%02X"):
            out.append(_e(form % cp, chr(cp), "python", "yaml"))
        digits = "%o" % cp
        for width in range(len(digits), 4):
            out.append(_e("\\" + digits.zfill(width), chr(cp), "python"))
    if cp < 0x10000:
        for form in ("\\u%04x", "\\u%04X"):
            out.append(_e(form % cp, chr(cp), "json", "python", "yaml"))
    for form in ("\\U%08x", "\\U%08X"):
        out.append(_e(form % cp, chr(cp), "python", "yaml"))
    for name in _names(cp):
        for spelled in (name, name.lower()):
            out.append(_e("\\N{%s}" % spelled, chr(cp), "python"))
    return out


def _dedupe(escapes):
    seen, out = {}, []
    for esc in escapes:
        if esc.spelling in seen:
            prior = seen[esc.spelling]
            assert prior.decoded == esc.decoded, esc
            continue
        seen[esc.spelling] = esc
        out.append(esc)
    return out


TABLE = _dedupe(ONE_CHAR + [e for cp in CODEPOINTS for e in _numeric(cp)])


# ── the real decoders ────────────────────────────────────────────────────────

def decode(grammar: str, spelling: str) -> str:
    quoted = '"' + spelling + '"'
    if grammar == "json":
        return json.loads(quoted)
    if grammar == "python":
        with warnings.catch_warnings():     # `\\X` is an invalid-escape warning, kept
            warnings.simplefilter("ignore")
            return ast.literal_eval(quoted)
    if grammar == "yaml":
        return yaml.safe_load(quoted)
    raise ValueError(grammar)


def decodings(spelling: str) -> tuple:
    """What each grammar that accepts the spelling decodes it to. Empty when
    none does, and then the raw reading is the only reading."""
    out = []
    for grammar in ("json", "python", "yaml"):
        try:
            got = decode(grammar, spelling)
        except Exception:                  # noqa: BLE001 -- a refusal is an answer
            continue
        if isinstance(got, str) and got not in out:
            out.append(got)
    return tuple(out)


# ── derived families: enumerated from the decoders' rules, decided by them ──
#
# 1. CASE FOLDING INSIDE \\N{name}. Python finds a character name ignoring
#    ASCII case only: the lookup upper-cases the name with an ASCII toupper,
#    so `\\N{line feed}` is a line feed and `\\N{L\u0130NE FEED}` is a
#    SyntaxError. The rule's regex engine folds wider. Under IGNORECASE it
#    equates some non-ASCII letters with ASCII ones, and FOLD_EQUIVALENTS asks
#    the engine which, over every codepoint there is, rather than listing them.
#    Every name the table spells is respelled with each equivalent in place of
#    each letter it equates to, upper-case name and lower-case name.
#
# 2. THE INTRODUCER IN THE OTHER CASE. Every table escape whose introducer is
#    a letter, with that letter's case swapped: `\\x0a` -> `\\X0a`, `\\u000a` ->
#    `\\U000a` (four digits after the eight-digit introducer), `\\U0000000a` ->
#    `\\u0000000a`, `\\N{...}` -> `\\n{...}`, `\\t` -> `\\T`.

_ASCII_LETTER = re.compile(r"[A-Za-z]", re.IGNORECASE)

FOLD_EQUIVALENTS = {
    chr(c): "".join(a for a in string.ascii_letters if re.fullmatch(a, chr(c), re.IGNORECASE))
    for c in range(0x80, 0x110000) if _ASCII_LETTER.fullmatch(chr(c))
}


@dataclasses.dataclass(frozen=True)
class Derived:
    spelling: str
    family: str
    readings: tuple         # decodings(spelling), whatever the decoders said


def _folded_names():
    out = []
    for cp in CODEPOINTS:
        for name in _names(cp):
            for base in (name, name.lower()):
                for i, letter in enumerate(base):
                    for fold, letters in FOLD_EQUIVALENTS.items():
                        if letter in letters:
                            out.append("\\N{%s}" % (base[:i] + fold + base[i + 1:]))
    return out


def _swapped_introducers():
    return ["\\" + e.spelling[1].swapcase() + e.spelling[2:]
            for e in TABLE if e.spelling[1:2].isascii() and e.spelling[1:2].isalpha()]


def _derive():
    known = {e.spelling for e in TABLE} | set(NOT_ESCAPES)
    out, seen = [], set()
    for family, spellings in (("name case fold", _folded_names()),
                              ("introducer case", _swapped_introducers())):
        for spelling in spellings:
            if spelling in known or spelling in seen:
                continue
            seen.add(spelling)
            out.append(Derived(spelling, family, decodings(spelling)))
    return out


DERIVED = _derive()


def self_check():
    """Every (spelling, grammar) pair the table claims, decoded for real.
    Returns the pairs that disagree; empty means the table is the grammar."""
    wrong = []
    for esc in TABLE:
        for grammar in sorted(esc.grammars):
            try:
                got = decode(grammar, esc.spelling)
            except Exception as exc:           # noqa: BLE001 -- the report is the point
                got = f"<{type(exc).__name__}>"
            if got != esc.decoded:
                wrong.append((esc.spelling, grammar, esc.decoded, got))
    return wrong


# ── the matrix ───────────────────────────────────────────────────────────────

# Where the escape sits. `{E}` is the escape, `{K}` the key. The prefix before a
# boundary is a word, so the boundary can only come from the escape.
POSITIONS = {
    "boundary": 'cfg: "prefix{E}{K}=' + PW + '"\n',
    "indentation": 'cfg: "{E}{K}=' + PW + '"\n',
    "after_escaped_newline": 'cfg: "prefix\\n{E}{K}=' + PW + '"\n',
    "separator": 'cfg: "{K}{E}=' + PW + '"\n',
    "equals": 'cfg: "{K}{E}' + PW + '"\n',
}


@dataclasses.dataclass(frozen=True)
class Case:
    position: str
    spelling: str
    key: str
    text: str
    expect_block: bool

    @property
    def name(self):
        return f"{self.position}:{self.spelling!r}:{self.key}"


def _readings(position, spelling, decoded):
    template = POSITIONS[position]
    raw = template.replace("{E}", spelling)
    dec = template.replace("{E}", decoded)
    if position == "after_escaped_newline":
        dec = dec.replace("prefix\\n", "prefix\n", 1)
    return raw, dec


def _reports(position, spelling, readings, k):
    """The parity contract: the raw reading, or any decoder's reading."""
    raw = _readings(position, spelling, spelling)[0].replace("{K}", k)
    return raw, literal_rule(raw) or any(
        literal_rule(_readings(position, spelling, d)[1].replace("{K}", k))
        for d in readings)


def cases():
    out = []
    items = ([(e.spelling, (e.decoded,)) for e in TABLE] + [(s, (s,)) for s in NOT_ESCAPES]
             + [(d.spelling, d.readings) for d in DERIVED])
    for n, (spelling, readings) in enumerate(items):
        key = KEYS[n % len(KEYS)]
        for position in POSITIONS:
            for k in (key, key.lower()):
                raw, block = _reports(position, spelling, readings, k)
                out.append(Case(position, spelling, k, raw, block))
    return out
