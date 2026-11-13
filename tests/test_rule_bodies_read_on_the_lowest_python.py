"""Every rule body reads on the lowest Python the package supports.

setup.py says `python_requires=">=3.9"`. A body written with a form that only newer Pythons
read (a possessive quantifier such as `a*+`, an atomic group such as `(?>a)`, the end-of-text
escape `\\z`) compiles on a developer's machine and fails at import on Python 3.9 and 3.10.
CI has 3.9 jobs, so the slip would be caught at the pull request, but only after a whole local
suite on a newer Python.

Three things are held here, on whichever Python runs the suite:
  1. every body of every rule the package ships compiles (this alone catches the slip on 3.9
     and 3.10, where those forms are errors);
  2. no body uses one of those forms, found by PARSING the body (possessive and atomic) and by
     reading its escapes (`\\z`), so a newer Python also fails the build, not only the 3.9 job;
  3. the lint on small examples: each form is found, the look-alikes are accepted.
There is no list of exceptions.
"""
import glob
import json
import os
import re

import pytest

try:  # 3.11+ keeps the parser under `re`; older versions only have sre_parse
    import re._constants as C
    import re._parser as P
except ImportError:  # pragma: no cover - exercised on 3.9 and 3.10
    import sre_constants as C
    import sre_parse as P

from sunglasses.mechanisms import MECHANISM_PATTERNS
from sunglasses.patterns import PATTERNS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NEWER_OPS = {
    name: getattr(C, name) for name in ("POSSESSIVE_REPEAT", "ATOMIC_GROUP") if hasattr(C, name)
}


def _as_list(value):
    if isinstance(value, str):
        return [value]
    return list(value or [])


def _all_bodies():
    """(rule id, body) for the built-in rules, the mechanism rules and the attack-db files."""
    out = []
    for rule in list(PATTERNS) + list(MECHANISM_PATTERNS):
        out.extend((rule["id"], body) for body in _as_list(rule.get("regex")))
    for path in sorted(glob.glob(os.path.join(ROOT, "attack-db", "attacks", "*", "*.json"))):
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        out.extend((data.get("id", os.path.basename(path)), body) for body in _as_list(data.get("regex")))
    return out


BODIES = _all_bodies()


def _walk(node, found):
    """Look at every (opcode, argument) pair in the parse tree. Opcodes are named integers, so
    a repeat count that happens to equal an opcode's number is not mistaken for one."""
    if isinstance(node, P.SubPattern):
        for item in node:
            _walk(item, found)
    elif isinstance(node, (tuple, list)):
        if node and type(node[0]) is type(C.LITERAL):
            for name, op in NEWER_OPS.items():
                if node[0] == op:
                    found.add(name)
        for item in node:
            _walk(item, found)


def _unescaped_end_of_text(body):
    """True when the body holds the escape `\\z` (read only by Python 3.14 and later)."""
    i = 0
    while i < len(body):
        if body[i] == "\\":
            if body[i + 1:i + 2] == "z":
                return True
            i += 2
        else:
            i += 1
    return False


def newer_python_forms(body):
    """The forms in a body that Python 3.9 cannot read, as a sorted list of names."""
    found = set()
    if _unescaped_end_of_text(body):
        found.add("END_OF_TEXT_ESCAPE")
    if NEWER_OPS:  # on 3.9 and 3.10 the compile test already fails for the other two forms
        try:
            _walk(P.parse(body), found)
        except re.error:
            pass
    return sorted(found)


def test_the_package_ships_bodies_to_check():
    assert len(BODIES) > 1000


def test_every_rule_body_compiles():
    bad = []
    for rule_id, body in BODIES:
        try:
            re.compile(body)
        except re.error as error:
            bad.append((rule_id, str(error)[:80]))
    assert bad == []


def test_no_rule_body_uses_a_form_the_lowest_python_cannot_read():
    bad = [(rule_id, newer_python_forms(body)) for rule_id, body in BODIES if newer_python_forms(body)]
    assert bad == []


@pytest.mark.parametrize("body, expected", [
    (r"abc\z", ["END_OF_TEXT_ESCAPE"]),
    (r"abc\Z", []),                    # the older spelling of the same thing
    (r"abc\\z", []),                   # an escaped backslash, then the letter z
    (r"[a\z]", ["END_OF_TEXT_ESCAPE"]),
    (r"(?i)\bword\b", []),
])
def test_the_lint_reads_escapes(body, expected):
    assert newer_python_forms(body) == expected


@pytest.mark.skipif(not NEWER_OPS, reason="this Python cannot parse the forms; its compile error is the test")
@pytest.mark.parametrize("body, expected", [
    (r"a*+", ["POSSESSIVE_REPEAT"]),
    (r"a++b", ["POSSESSIVE_REPEAT"]),
    (r"(?:ab){2,3}+c", ["POSSESSIVE_REPEAT"]),
    (r"(?>ab)c", ["ATOMIC_GROUP"]),
    (r"a*?b", []),                     # lazy, older Pythons read it
    (r"a\++", []),                     # an escaped plus, then a plain repeat
    (r"[*+]+", []),                    # characters in a class, then a plain repeat
    (r"(?:a|b)*c", []),
])
def test_the_lint_reads_the_parse_tree(body, expected):
    assert newer_python_forms(body) == expected
