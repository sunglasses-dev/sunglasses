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
    """The haystack view every prefilter test runs against.

    Translate BEFORE lowering. `"\u0130".lower()` is TWO codepoints, an ASCII
    `i` followed by COMBINING DOT ABOVE, so lowering first splits the character
    the table is meant to collapse and the fold silently fails on it.
    """
    return text.translate(_CASEFOLD).lower()


def _pick(clauses):
    """One clause from a branch, chosen for selectivity.

    Any single clause of a branch is implied by that branch matching, so
    picking one is sound. Prefer the clause whose weakest literal is longest.
    """
    if not clauses:
        return None
    return max(clauses, key=lambda c: min(len(l) for l in c))


def _ascii_literal(av):
    """The lowercase ASCII character this LITERAL contributes, or None.

    A non-ASCII literal contributes NOTHING and breaks the run. Two reasons,
    both found by execution (ASTRA, 2026-09-10):

      `chr(0x130).lower()` is two codepoints, so lowercasing here injected a
      COMBINING DOT ABOVE into the requirement that the matching document never
      had to contain -- the fold order was fixed in `fold()` and this earlier
      conversion still had it.

      More fundamentally, lowercase-plus-four-exceptions is not a general
      Unicode equivalence rule. It is exhaustive for characters equivalent to
      ASCII LETTERS, which is a different claim. Greek final sigma and the micro
      sign match their regexes and defeat that mapping, and sigma's lowercasing
      is context sensitive besides, which a per-character extractor cannot see.

    Restricting derivation to ASCII removes the whole class rather than adding
    another table. Anything non-ASCII is simply evaluated, as before.
    """
    ch = chr(av)
    if ch.isascii():
        return ch.lower()
    return None


def _leading_run(seq):
    """The ASCII literal characters one parsed sequence must start with."""
    run = []
    for op, av in seq:
        if str(op) != "LITERAL":
            break
        ch = _ascii_literal(av)
        if ch is None:
            break
        run.append(ch)
    return "".join(run)


def _clauses(seq):
    """CNF clauses required by one parsed sequence."""
    out, cur = [], []
    prefix = ""

    def flush():
        nonlocal prefix
        run = "".join(cur)
        cur.clear()
        prefix = run
        if len(run) >= MIN_LITERAL:
            out.append(frozenset({run}))

    for op, av in seq:
        name = str(op)
        if name == "LITERAL":
            ch = _ascii_literal(av)
            if ch is not None:
                cur.append(ch)
                continue
            # A non-ASCII literal is not derivable, so it ends the run exactly
            # like a wildcard would. The ASCII prefix before it is still a
            # necessary substring and is kept.
            flush()
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
            # `prefix` is the literal run that ran up to this alternation and
            # was just flushed. It is required whichever branch is taken, and
            # sre_parse FACTORS it out of the branches: `(previous|prior)`
            # arrives as p, r, BRANCH(evious|ior), where every piece alone is
            # under MIN_LITERAL. Recombining recovers {previous, prior}.
            alts = []
            for b in branches:
                lead = _leading_run(b)
                whole = prefix + lead
                if len(whole) >= MIN_LITERAL:
                    alts.append(frozenset({whole}))
                else:
                    alts.append(_pick(_clauses(b)))
            # One unconstrained branch and the alternation constrains nothing.
            if alts and all(a is not None for a in alts):
                merged = frozenset().union(*alts)
                if all(len(l) >= MIN_LITERAL for l in merged):
                    out.append(merged)
            prefix = ""
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
        if f and f not in seen and all(
                len(l) >= MIN_LITERAL and l.isascii() for l in f):
            seen.add(f)
            folded.append(f)
    return tuple(folded)


# Opcodes that consume exactly one character.
_ONE_CHAR = {"LITERAL", "NOT_LITERAL", "ANY", "IN", "RANGE", "CATEGORY"}
# Opcodes that consume nothing: anchors and lookarounds.
_ZERO_WIDTH = {"AT", "ASSERT", "ASSERT_NOT", "NEGATE"}


def _max_len(seq):
    """Longest string this parse tree can consume, or None when unbounded.

    Deliberately conservative: an opcode this does not recognise returns None,
    because the only caller uses the number to bound a search window and a bound
    that is too small silently loses matches.
    """
    total = 0
    for op, av in seq:
        name = getattr(op, "name", str(op))
        if name in _ZERO_WIDTH:
            continue
        if name in _ONE_CHAR:
            total += 1
        elif name == "SUBPATTERN":
            inner = _max_len(av[3])
            if inner is None:
                return None
            total += inner
        elif name == "ATOMIC_GROUP":
            inner = _max_len(av)
            if inner is None:
                return None
            total += inner
        elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            _, hi, sub = av
            if hi >= _sre_parse.MAXREPEAT:
                return None
            inner = _max_len(sub)
            if inner is None:
                return None
            total += hi * inner
        elif name == "BRANCH":
            widest = 0
            for branch in av[1]:
                inner = _max_len(branch)
                if inner is None:
                    return None
                widest = max(widest, inner)
            total += widest
        else:
            return None                      # GROUPREF, GROUPREF_EXISTS, ...
    return total


def max_match_length(pattern_source: str):
    """Longest match this regex can produce, or None when it is unbounded."""
    try:
        return _max_len(_sre_parse.parse(pattern_source, re.IGNORECASE))
    except Exception:
        return None


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
