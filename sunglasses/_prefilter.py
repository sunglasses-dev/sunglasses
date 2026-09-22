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


def _class_requirement(seq):
    """A ClassClause when this branch cannot match without one of its characters.

    Only for the unambiguous shape: a bare character class repeated at least
    once, with nothing else in the branch that could carry the match. Anything
    less certain returns None, because a wrong clause here would SKIP a regex
    that could have matched, and a missed skip only costs time.
    """
    # A capturing group around the class is the common shape: `([\u2800-\u28FF]{8,})`
    core = [(op, av) for op, av in seq if str(op) != "AT"]
    if len(core) == 1 and str(core[0][0]) == "SUBPATTERN":
        return _class_requirement(core[0][1][-1])

    ranges, seen_repeat = [], False
    for op, av in seq:
        name = str(op)
        if name in ("MAX_REPEAT", "MIN_REPEAT"):
            lo, _hi, item = av
            if lo < 1 or len(item) != 1 or str(item[0][0]) != "IN":
                return None
            got = _class_ranges(item[0][1])
            if not got:
                return None
            ranges, seen_repeat = got, True
        elif name == "IN":
            got = _class_ranges(av)
            if not got:
                return None
            ranges, seen_repeat = got, True
        elif name == "AT":
            continue
        else:
            return None          # something else could carry the match
    if not seen_repeat or not ranges:
        return None
    return ClassClause(ranges)


# A class wider than this is not selective enough to be worth proving, and the
# proof below walks every codepoint in it.
MAX_CLASS_CODEPOINTS = 4096


def _case_inert(ch: str) -> bool:
    """True when no case operation and no fold can move this character.

    The clause is answered against pages of the FOLDED document while the pages
    were recorded from the class as written, so any character the class can
    match must fold to the same page or the clause is wrong in the unsafe
    direction. `[K-Å]` on a document of KELVIN SIGN U+212A is the worked case:
    `re.IGNORECASE` matches it against `K`, `fold` turns it into `k` on page 0,
    the recorded page 0x21 is absent, and a rule that WOULD have matched is
    skipped.

    Rather than build a reverse case map, require every character in the class
    to be inert. A character that is not the result of any case mapping is
    itself uncased, and every character that case folds into another is a cased
    letter whose own upper or lower differs from itself, so the test excludes
    both directions. `test_the_recorded_pages_hold_for_every_codepoint` proves
    that exhaustively over the classes that actually gain a clause, rather than
    leaving it as an argument.
    """
    return (ch.lower() == ch and ch.upper() == ch
            and ch.casefold() == ch and fold(ch) == ch)


def _class_ranges(items):
    """Ranges of a positive character class, or None if it is negated/complex."""
    out = []
    for op, av in items:
        name = str(op)
        if name == "NEGATE":
            return None          # a negated class matches almost everything
        if name == "RANGE":
            out.append((av[0], av[1]))
        elif name == "LITERAL":
            out.append((av, av))
        else:
            return None          # CATEGORY (\w, \s ...) is far too broad
    if not out:
        return None
    if sum(hi - lo + 1 for lo, hi in out) > MAX_CLASS_CODEPOINTS:
        return None
    for lo, hi in out:
        for cp in range(lo, hi + 1):
            if not _case_inert(chr(cp)):
                return None      # case can move it off the recorded page
    return out


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
                    picked = _pick(_clauses(b))
                    if picked is None:
                        # No literal anywhere in this branch. It may still
                        # require a CHARACTER CLASS, which is a real clause.
                        picked = _class_requirement(b)
                    alts.append(picked)
            # One unconstrained branch and the alternation constrains nothing.
            if alts and all(a is not None for a in alts):
                lits, klasses = set(), []
                for a in alts:
                    if isinstance(a, ClassClause):
                        klasses.append(a)
                    elif isinstance(a, Clause):
                        # A NESTED alternation arrives here as an inner Clause.
                        # Iterating it yields its literals only, so `set(a)`
                        # kept the literals and silently DROPPED its classes,
                        # turning `decode OR braille` into `decode` and making
                        # a necessary condition STRONGER than the regex. Both
                        # halves have to come out.
                        lits |= set(a.literals)
                        klasses.extend(a.classes)
                    else:
                        lits |= set(a)
                if all(len(l) >= MIN_LITERAL for l in lits):
                    out.append(Clause(lits, klasses) if klasses else frozenset(lits))
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


PAGE_SHIFT = 8          # a codepoint "page" is 256 characters wide


class ClassClause:
    """A branch that requires at least one character from a set of ranges.

    A bare character class under `+` or `{n,}` carries no literal, so the CNF
    deriver used to return NOTHING for the whole regex it sits in — one such
    branch made every other branch in that regex unskippable, and the rule then
    ran on every document. `GLS-ENC-ALT-210` is the worked example: a braille
    class beside a base64 branch cost 255 seconds on a 27 KB document that could
    not possibly match either.

    The branch does require something, just not a literal: at least one
    character inside its ranges. That is a clause, and it is cheap to answer.
    """

    __slots__ = ("ranges", "pages")

    def __init__(self, ranges):
        self.ranges = tuple(sorted(ranges))
        # Every 256-character page the ranges touch. Answering "is any character
        # of this class present" then costs a set intersection rather than a
        # scan, and the page set for a document is computed once.
        # Recorded from what `fold` PRODUCES for each character, because the
        # document these pages are compared against is folded. `_class_ranges`
        # only admits characters fold leaves alone, so the two agree, and
        # computing it this way means a future fold change shows up here.
        pages = set()
        for lo, hi in self.ranges:
            for cp in range(lo, hi + 1):
                for ch in fold(chr(cp)):
                    pages.add(ord(ch) >> PAGE_SHIFT)
        self.pages = frozenset(pages)

    def satisfied_by(self, pages_present) -> bool:
        """Conservative: pages OVERLAP means a character MIGHT be present."""
        return bool(self.pages & pages_present)

    def __repr__(self):
        return f"ClassClause({[(hex(a), hex(b)) for a, b in self.ranges]})"


class Clause:
    """One CNF clause: the document must contain a literal OR a class character.

    A plain literal clause is still just a frozenset elsewhere in this module;
    this type appears only when an alternation mixes literals with a branch whose
    requirement is a character class.
    """

    __slots__ = ("literals", "classes")

    def __init__(self, literals=(), classes=()):
        self.literals = frozenset(literals)
        self.classes = tuple(classes)

    def satisfied_by(self, presence) -> bool:
        for lit in self.literals:
            if presence.has_literal(lit):
                return True
        return any(c.satisfied_by(presence.pages) for c in self.classes)

    # A clause used to be a plain frozenset of literals and several callers
    # still treat it as one. Iterating yields the LITERAL half, which is what
    # every one of them wants; the class half is reached through `.classes`.
    def __iter__(self):
        return iter(self.literals)

    def __len__(self):
        return len(self.literals)

    def __contains__(self, item):
        return item in self.literals

    def __repr__(self):
        # THE COUNT IS PART OF THE TRUTH. This printed only the first three
        # literals, so a clause holding seven read as three and looked like a
        # prefilter that should have skipped a document it had correctly run.
        # That nearly became a reported engine bug during the ENC-ALT-210
        # measurement (2026-09-13): the requirement PRINTS as
        # ['apply','base64','convert'] while also holding 'decode', which was
        # in the document and is exactly why `can_skip` was correctly False.
        # A repr that silently truncates is a repr that misleads whoever is
        # debugging; if you are deciding from it, call `has_literal` /
        # `can_skip` directly -- but it should not invite the mistake.
        shown = sorted(self.literals)[:3]
        more = len(self.literals) - len(shown)
        lits = f"{shown}{f' +{more} more' if more > 0 else ''}"
        return f"Clause(literals={lits}, classes={list(self.classes)})"


def pages_of(text: str) -> frozenset:
    """The 256-character pages this document touches. One pass."""
    return frozenset(ord(ch) >> PAGE_SHIFT for ch in set(text))


class Presence:
    """What a document contains, as the skip test needs it."""

    __slots__ = ("literals", "text", "pages")

    def __init__(self, literals, text, pages):
        self.literals = literals      # set, or None when there is no index
        self.text = text              # folded text, kept for the fallback path
        self.pages = pages

    def has_literal(self, lit) -> bool:
        if self.literals is not None:
            return lit in self.literals
        return lit in self.text


def requirement(pattern_source: str):
    """CNF requirement for one regex source, or () when nothing is derivable."""
    try:
        parsed = _sre_parse.parse(pattern_source, re.IGNORECASE)
        clauses = _clauses(parsed)
    except Exception:
        return ()
    folded, seen = [], set()
    for c in clauses:
        if isinstance(c, Clause):
            lits = frozenset(fold(l) for l in c.literals)
            if lits and not all(len(l) >= MIN_LITERAL and l.isascii() for l in lits):
                continue
            key = (lits, c.classes)
            if key in seen:
                continue
            seen.add(key)
            folded.append(Clause(lits, c.classes))
            continue
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


# Every node kind that can carry a subpattern. A walker that does not enter one
# of these cannot see what is inside it, and for `_has_lookaround` "cannot see"
# reads as "there is none", which is the R1a defect: a lookahead inside a
# conditional stayed invisible, the rule stayed anchored, and the finding was
# lost. Enumerated rather than discovered one bug at a time, and
# `test_every_container_node_kind_is_walked` fails if a future interpreter adds
# a kind that is not in here.
_CONTAINERS = frozenset({
    "SUBPATTERN", "ATOMIC_GROUP", "MAX_REPEAT", "MIN_REPEAT",
    "POSSESSIVE_REPEAT", "BRANCH", "GROUPREF_EXISTS", "ASSERT", "ASSERT_NOT",
})


def _subtrees(name, av):
    """The subpatterns hanging off one node, whatever kind it is."""
    if name == "SUBPATTERN":
        return (av[3],)
    if name == "ATOMIC_GROUP":
        return (av,)
    if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
        return (av[2],)
    if name == "BRANCH":
        return tuple(av[1])
    if name in ("ASSERT", "ASSERT_NOT"):
        return (av[1],)
    if name == "GROUPREF_EXISTS":
        # `(?(1)yes|no)`. BOTH arms, and the no-arm may be absent. Walking only
        # the yes-arm would have left half of this hole open.
        return tuple(arm for arm in (av[1], av[2]) if arm)
    return ()


def _has_lookaround(seq) -> bool:
    """True when this tree contains a lookahead or lookbehind.

    `\b`, `^` and `$` are AT nodes and are NOT lookarounds; they are answered
    from the neighbouring characters, which a bounded search still has.
    """
    for op, av in seq:
        name = getattr(op, "name", str(op))
        if name in ("ASSERT", "ASSERT_NOT"):
            return True
        if any(_has_lookaround(sub) for sub in _subtrees(name, av)):
            return True
    return False


def has_lookaround(pattern_source: str) -> bool:
    """True when the regex contains a lookahead or lookbehind, or cannot be read."""
    try:
        return _has_lookaround(_sre_parse.parse(pattern_source, re.IGNORECASE))
    except Exception:
        return True                              # unreadable, assume the worst


def max_match_length(pattern_source: str):
    """Longest match this regex can produce, or None when it is unbounded."""
    try:
        return _max_len(_sre_parse.parse(pattern_source, re.IGNORECASE))
    except Exception:
        return None


def can_skip(req, present) -> bool:
    """True when the regex provably cannot match.

    `present` is a Presence, the set of literals found in the document, or the
    folded text itself when no index is in use. A clause may require a literal,
    a character class, or either.
    """
    if isinstance(present, Presence):
        for clause in req:
            if isinstance(clause, Clause):
                if not clause.satisfied_by(present):
                    return True
            elif not any(present.has_literal(l) for l in clause):
                return True
        return False
    # Legacy callers: a bare set of literals, or the folded text. A class clause
    # cannot be answered without the document, so it is treated as satisfiable,
    # which costs a scan and never a finding.
    if isinstance(present, str):
        for clause in req:
            lits = clause.literals if isinstance(clause, Clause) else clause
            if isinstance(clause, Clause) and clause.classes:
                if any(l in present for l in lits):
                    continue
                if any(c.satisfied_by(pages_of(present)) for c in clause.classes):
                    continue
                return True
            if not any(l in present for l in lits):
                return True
        return False
    for clause in req:
        if isinstance(clause, Clause):
            if clause.classes:
                continue          # unanswerable here, do not skip
            if present.isdisjoint(clause.literals):
                return True
        elif present.isdisjoint(clause):
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
                self._literals |= set(
                    clause.literals if isinstance(clause, Clause) else clause)
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
        """What the document contains: literals found, plus its codepoint pages.

        The pages are what answers a ClassClause, and they cost one pass over
        the set of distinct characters rather than a scan per class.
        """
        literals = None
        if self._automaton is not None:
            literals = {found for _end, found in self._automaton.iter(folded_text)}
        return Presence(literals, folded_text, pages_of(folded_text))
