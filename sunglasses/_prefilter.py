"""Required-literal prefilter for the step-3 regex sweep.

Step 3 evaluates all 1,578 pattern regexes against the whole document on every
scan, which is where a 1 MB scan spends its 52 seconds and where CI spends
hours. Most of those regexes cannot possibly match the document in front of
them, and the regex itself says so: if a string the regex MUST contain is
absent, evaluation is dead work.

The requirement is derived from the regex's own parse tree, never from declared
keywords. Declared keywords are hints, not necessary conditions -- the earlier
keyword-gate prototype dropped GLS-CF-252 on the plain "Ignore all previous
instructions" attack because that pattern's declared keywords are long phrases
that never appear in the payload.

MODEL: a requirement is a conjunction of disjunctions (CNF). Each clause is a
set of alternative literals; the regex can match only if EVERY clause has at
least one of its literals present. `(?:ignore|bypass)\\b.{0,120}\\b(previous|
prior)` yields two clauses, {ignore, bypass} and {previous, prior}, and a
document missing either family is skipped.

Every derivation rule errs toward extracting LESS. An empty requirement means
"no prefilter, evaluate as before", which is always correct.
"""
import re

try:
    from re import _parser as _sre_parse          # 3.11+
except ImportError:                                # pragma: no cover
    import sre_parse as _sre_parse

# Every pattern regex is compiled with re.IGNORECASE, so the prefilter tests a
# lowercased view. IGNORECASE also equates four non-ASCII codepoints with ASCII
# letters, and .lower() collapses only two of them. Computed exhaustively over
# the whole Unicode range, not assumed:
#     i <- U+0130 U+0131     k <- U+212A     s <- U+017F
# Without this fold, "ıgnore" with a dotless i matches the regex while the
# prefilter skips it -- the prefilter would BE an evasion channel, in a scanner
# whose adversary uses homoglyphs on purpose. Do not drop this table.
_CASEFOLD = str.maketrans({"İ": "i", "ı": "i", "K": "k", "ſ": "s"})

MIN_LITERAL = 4       # below this a literal is not selective enough to pay for


def fold(text: str) -> str:
    """The haystack view every prefilter test runs against."""
    return text.lower().translate(_CASEFOLD)


def _pick(clauses):
    """One clause from a branch, chosen for selectivity.

    Any single clause of a branch is implied by that branch matching, so
    picking one is sound. Prefer the clause whose weakest literal is longest.
    """
    if not clauses:
        return None
    return max(clauses, key=lambda c: min(len(l) for l in c))


def _clauses(seq):
    """CNF clauses required by one parsed sequence."""
    out, cur = [], []

    def flush():
        run = "".join(cur)
        cur.clear()
        if len(run) >= MIN_LITERAL:
            out.append(frozenset({run}))

    for op, av in seq:
        name = str(op)
        if name == "LITERAL":
            cur.append(chr(av).lower())
            continue
        flush()
        if name == "SUBPATTERN":
            item = av[-1]
            add, dele = (av[1], av[2]) if len(av) == 4 else (0, 0)
            # Adding IGNORECASE is a no-op here (the whole regex already has
            # it); any other flag change could alter case semantics, so stop.
            if not dele and not (add & ~re.IGNORECASE):
                out.extend(_clauses(item))
        elif name in ("MAX_REPEAT", "MIN_REPEAT"):
            mn, _mx, item = av
            if mn >= 1:
                out.extend(_clauses(item))
        elif name == "BRANCH":
            _, branches = av
            picks = [_pick(_clauses(b)) for b in branches]
            # One unconstrained branch and the alternation constrains nothing.
            if picks and all(p is not None for p in picks):
                merged = frozenset().union(*picks)
                if all(len(l) >= MIN_LITERAL for l in merged):
                    out.append(merged)
        elif name == "ASSERT":
            direction, item = av
            # Positive lookahead AND lookbehind both require their contents to
            # appear in the document. Negative assertions require nothing.
            if direction in (1, -1):
                out.extend(_clauses(item))
        elif name == "ATOMIC_GROUP":
            out.extend(_clauses(av))
        # IN / ANY / AT / CATEGORY / GROUPREF / ASSERT_NOT and anything
        # unrecognised contribute nothing.
    flush()
    return out


def requirement(pattern_source: str):
    """CNF requirement for one regex source, or () when nothing is derivable."""
    try:
        parsed = _sre_parse.parse(pattern_source, re.IGNORECASE)
        clauses = _clauses(parsed)
    except Exception:
        return ()
    folded, seen = [], set()
    for c in clauses:
        f = frozenset(fold(l) for l in c)
        if f and f not in seen and all(len(l) >= MIN_LITERAL for l in f):
            seen.add(f)
            folded.append(f)
    return tuple(folded)


def can_skip(req, present) -> bool:
    """True when the regex provably cannot match.

    `present` is the set of required literals actually found in the document
    (see LiteralIndex), or the folded text itself when no index is in use.
    """
    if isinstance(present, str):
        for clause in req:
            if not any(l in present for l in clause):
                return True
        return False
    for clause in req:
        if present.isdisjoint(clause):
            return True
    return False


class LiteralIndex:
    """One pass over the document instead of one scan per literal.

    With 1,578 regexes the naive form runs thousands of independent substring
    searches over the same megabyte -- 2.0 s of a 27 s scan, measured. Every
    one of those literals can be found in a single Aho-Corasick sweep, after
    which a skip decision is set membership. Falls back to per-literal search
    when the optional automaton library is absent, which is slower but
    identical in outcome.
    """

    def __init__(self, requirements):
        self._literals = set()
        for req in requirements:
            for clause in req:
                self._literals |= set(clause)
        self._automaton = None
        if not self._literals:
            return
        try:
            import ahocorasick
        except ImportError:
            return
        try:
            a = ahocorasick.Automaton()
            for lit in self._literals:
                a.add_word(lit, lit)
            a.make_automaton()
        except Exception:
            return
        self._automaton = a

    def present(self, folded_text: str):
        """Literals actually in the document, or the text itself if no index."""
        if self._automaton is None:
            return folded_text
        return {found for _end, found in self._automaton.iter(folded_text)}
