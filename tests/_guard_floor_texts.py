"""Texts for tests/test_guard_floor.py: built from a rule's own regex, never typed by hand.

`text_for(source)` returns a text the regex accepts, walked from its parse tree. `hit_texts(body)`
returns, for a negative guard body, one text per alternative of every branch in it (a word and a
phrase alike), each of which the guard accepts on its own.
"""
import re

try:
    from re import _constants as C
    from re import _parser as P
except ImportError:                      # Python < 3.11
    import sre_constants as C
    import sre_parse as P

_POSSESSIVE = getattr(C, "POSSESSIVE_REPEAT", None)
_ATOMIC = getattr(C, "ATOMIC_GROUP", None)
_WORD = {C.CATEGORY_DIGIT: "1", C.CATEGORY_SPACE: " ", C.CATEGORY_WORD: "a"}


def _class_char(items):
    negated = any(op is C.NEGATE for op, _ in items)
    members = [(op, av) for op, av in items if op is not C.NEGATE]
    if not negated:
        for op, av in members:
            if op is C.LITERAL:
                return chr(av)
            if op is C.RANGE:
                return chr(av[0])
            if op is C.CATEGORY:
                return _WORD.get(av, "a")
        return "a"

    def inside(ch):
        for op, av in members:
            if op is C.LITERAL and ord(ch) == av:
                return True
            if op is C.RANGE and av[0] <= ord(ch) <= av[1]:
                return True
            if op is C.CATEGORY:
                if av is C.CATEGORY_DIGIT and ch.isdigit():
                    return True
                if av is C.CATEGORY_SPACE and ch.isspace():
                    return True
                if av is C.CATEGORY_WORD and (ch.isalnum() or ch == "_"):
                    return True
        return False
    for ch in "a1 .-z":
        if not inside(ch):
            return ch
    return "~"


def _walk(seq, forced):
    out = []
    for op, av in seq:
        if op is C.LITERAL:
            out.append(chr(av))
        elif op is C.NOT_LITERAL:
            out.append("a" if av != ord("a") else "b")
        elif op is C.ANY:
            out.append("a")
        elif op is C.IN:
            out.append(_class_char(av))
        elif op is C.BRANCH:
            choice = forced.get(id(av), 0)
            out.append(_walk(av[1][choice] if choice < len(av[1]) else av[1][0], forced))
        elif op is C.SUBPATTERN:
            out.append(_walk(av[3], forced))
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT, _POSSESSIVE):
            lo, _hi, sub = av
            out.append(_walk(sub, forced) * lo)
        elif op is C.ASSERT:
            out.append(" " + _walk(av[1], forced) + " ")
        elif _ATOMIC is not None and op is _ATOMIC:
            out.append(_walk(av, forced))
        elif op is C.CATEGORY:
            out.append(_WORD.get(av, "a"))
        elif op is C.AT and av is C.AT_BOUNDARY:
            out.append(" ")             # a word edge: the words either side of it are apart
    return "".join(out)


def _branches(seq, found):
    for op, av in seq:
        if op is C.BRANCH:
            found.append(av)
            for alt in av[1]:
                _branches(alt, found)
        elif op is C.SUBPATTERN:
            _branches(av[3], found)
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT, _POSSESSIVE):
            _branches(av[2], found)
        elif op is C.ASSERT or op is C.ASSERT_NOT:
            _branches(av[1], found)
        elif _ATOMIC is not None and op is _ATOMIC:
            _branches(av, found)


def _tidy(text):
    return re.sub(r"[ ]{2,}", " ", text).strip()


def text_for(source):
    """A text `source` accepts when nothing else in the rule objects, or None."""
    try:
        tree = P.parse(source, 0)
    except Exception:
        return None
    return _tidy(_walk(tree.data, {})) or None


def hit_texts(body):
    """One text per alternative of every branch in a guard body (the rest of the body at its first
    alternative). The guard is checked against the text by the caller."""
    try:
        tree = P.parse(body, 0)
    except Exception:
        return []
    branches = []
    _branches(tree.data, branches)
    texts = []
    seen = set()
    first = _tidy(_walk(tree.data, {}))
    if first:
        seen.add(first)
        texts.append(first)
    for node in branches:
        for index in range(len(node[1])):
            text = _tidy(_walk(tree.data, {id(node): index}))
            if text and text not in seen:
                seen.add(text)
                texts.append(text)
    return texts
