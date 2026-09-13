"""Generate a minimal matching sample for every branch of a marker alternation.

The point is to stop hand-maintaining a keyword list that has to equal the set
of markers the regex accepts. Walk the SAME parse tree `_prefilter` walks, emit
a sample per branch, and let the suite prove every one of them routes.
"""
import re as _re
import string as _string
try:
    import re._parser as sre_parse
except ImportError:                                   # pragma: no cover
    import sre_parse


def _emit(node, spaced, pick=None, counter=None, optional=None):
    """A minimal string matching one parsed sequence.

    `spaced` widens a zero-or-more to one repetition, which is how the tag
    spacing variants (`< / admin >`) get generated.

    `pick` is a VECTOR: a mapping from an alternation node to which of its
    alternatives to take, so alternations can be varied TOGETHER. It used to be
    a single (which alternation, which alternative) pair, which varied one
    alternation at a time and left every other one on its first alternative.
    For `ignore (?:old|stale) (?:local|remote) policy` that yields
    `ignore stale local policy` and `ignore old remote policy` and never
    `ignore stale remote policy`, which is the reviewer's round 9 witness: a
    marker the regex accepts that the sampler could not produce, so nothing
    could ask whether it routes.

    The key is the alternation's own alternatives list, not a position in a
    traversal, because a traversal only enters the alternative it picked and
    the numbering would shift underneath the vector.

    `optional` is `[counter, choices]`, where `choices` maps an optional group's
    index to how many repetitions it should take. `s?` and `(?:...)?` are
    branches of the marker grammar, and emitting only one side of them is how
    `guardrail` stayed invisible while `guardrails` was covered.
    """
    out = []
    for op, av in node:
        name = str(op)
        if name == "LITERAL":
            out.append(chr(av))
        elif name == "NOT_LITERAL":
            out.append("x" if chr(av) != "x" else "y")
        elif name == "ANY":
            out.append("x")
        elif name == "IN":
            out.append(_from_class(av))
        elif name in ("MAX_REPEAT", "MIN_REPEAT"):
            lo, hi, item = av
            if lo == 0 and 1 <= hi < sre_parse.MAXREPEAT and optional is not None:
                # An OPTIONAL group is a branch of the marker grammar like any
                # other. Round 9 walked one arm at a time, which covers
                # `guardrails?` but not two independent optionals BOTH absent
                # (`\bfoos?\s+bars?\b` never produced `foo bar`) and not the
                # upper end of a `{0,2}`. The choice vector says how many
                # repetitions THIS group takes, so a caller can ask for all
                # present, one absent, all absent, or a group at its maximum.
                here = optional[0]
                optional[0] += 1
                chosen = (optional[1] or {}).get(here)
                reps = 1 if chosen is None else min(chosen, hi)
            else:
                reps = lo if lo else (1 if spaced else 0)
            out.append(_emit(item, spaced, pick, counter, optional) * max(reps, 0))
        elif name == "SUBPATTERN":
            out.append(_emit(av[-1], spaced, pick, counter, optional))
        elif name == "BRANCH":
            alts = av[1]
            idx = 0
            if pick:
                idx = pick.get(id(alts), 0) % len(alts)
            out.append(_emit(alts[idx], spaced, pick, counter, optional))
        elif name in ("AT", "ASSERT", "ASSERT_NOT"):
            continue
        elif name == "ATOMIC_GROUP":
            out.append(_emit(av, spaced, pick, counter, optional))
    return "".join(out)


# Full product up to here, pairwise beyond. 960 is the widest sibling today.
MAX_PICK_VECTORS = 4000


def alternations(node, table=None):
    """Every alternation in this tree, keyed by its own alternatives list.

    Walks into EVERY alternative, not only the one a pick would take, so the
    keys are stable whatever the vector says. Returns key -> how many
    alternatives it offers.
    """
    table = {} if table is None else table
    for op, av in node:
        name = str(op)
        if name == "BRANCH":
            table.setdefault(id(av[1]), len(av[1]))
            for branch in av[1]:
                alternations(branch, table)
        elif name == "SUBPATTERN":
            alternations(av[-1], table)
        elif name in ("MAX_REPEAT", "MIN_REPEAT"):
            alternations(av[2], table)
        elif name == "ATOMIC_GROUP":
            alternations(av, table)
    return table


def pick_vectors(sizes, cap=MAX_PICK_VECTORS):
    """Which combinations of alternatives to emit.

    The full product where it fits, because these markers are small: the widest
    sibling is 960 combinations. Where it does not fit, every PAIR of choices,
    which is the combinatorial-testing standard and still covers the reviewer's
    witness, since `stale` with `remote` is a pair. The caller is told which
    regime it got rather than left to assume the stronger one.
    """
    import itertools
    keys = list(sizes)
    total = 1
    for key in keys:
        total *= sizes[key]
    if total <= cap:
        return [dict(zip(keys, combo))
                for combo in itertools.product(*(range(sizes[k]) for k in keys))], "full"
    vectors = [{}]
    for key in keys:
        vectors += [{key: i} for i in range(1, sizes[key])]
    for left, right in itertools.combinations(keys, 2):
        for i in range(sizes[left]):
            for j in range(sizes[right]):
                vectors.append({left: i, right: j})
    return vectors, "pairwise"


_SPACE = [' ']          # swapped to a newline for the third variant
MAX_NESTED_ALTS = 24   # widest nested alternation in the sibling markers
MAX_OPTIONAL_ARMS = 24  # most optional arms in any one marker branch
MAX_OPTIONAL_REPS = 4   # the top of a bounded repeat, clamped per group


_GAP_PREFERENCE = (" ", "x", "a", "0", "-", "_")


def _excluded_by(items):
    """Every character the members of a class name, expanded."""
    out = set()
    for op, av in items:
        n = str(op)
        if n == "LITERAL":
            out.add(chr(av))
        elif n == "RANGE":
            out.update(chr(c) for c in range(av[0], av[1] + 1))
        elif n == "CATEGORY":
            c = str(av)
            if "SPACE" in c:
                out.update(" \t\r\n\f\v")
            elif "DIGIT" in c:
                out.update("0123456789")
            elif "WORD" in c:
                out.update(_string.ascii_letters + _string.digits + "_")
    return out


def _from_class(items):
    """One character the class accepts.

    A NEGATED class needs a character it does NOT name. The first version read
    past the NEGATE marker and returned the first LITERAL it found, so `[^.\n]`
    emitted `.`, the one character it forbids. Every sample for the two marker
    SEQUENCES came out as `ignore.policy`, the marker rejected all of them, the
    valid-sample filter dropped the whole family, and the coverage theorem was
    then quantifying over nothing for two of the six rules.

    A space is preferred wherever the class allows one, because these gaps sit
    between words the marker bounds with `\b`, and any non-space filler welds
    the words together and fails the boundary just as surely.
    """
    if any(str(op) == "NEGATE" for op, _ in items):
        excluded = _excluded_by([(op, av) for op, av in items if str(op) != "NEGATE"])
        for ch in _GAP_PREFERENCE:
            if ch not in excluded:
                return ch
        return "x"
    for op, av in items:
        n = str(op)
        if n == "LITERAL":
            return chr(av)
        if n == "RANGE":
            return chr(av[0])
        if n == "CATEGORY":
            c = str(av)
            if "SPACE" in c:
                return _SPACE[0]
            if "DIGIT" in c:
                return "0"
            return "a"
    return "x"


def branch_samples(marker_source):
    """(branch_index, sample) pairs: minimal and one-space forms of every branch."""
    parsed = sre_parse.parse(marker_source, _re.IGNORECASE)

    def top_alternation(seq):
        """The branches of a marker that IS one alternation, else None.

        Only a marker whose whole body is an alternation has branches worth
        enumerating. A marker that is a SEQUENCE (`verb ... object`) happens to
        contain alternations for its verb list and its object list, and treating
        those as marker branches produces samples like "ignore" or "policy" on
        their own, which the marker does not actually accept.
        """
        # `\b` parses to an AT node, so the alternation is rarely the ONLY
        # node. Ignore zero-width anchors when deciding whether this sequence is
        # just an alternation; missing that capped GLS-PI-021 at the first eight
        # of its sixteen markers, and "grandmother used to" is the fourteenth.
        core = [(op, av) for op, av in seq if str(op) != "AT"]
        if len(core) == 1:
            op, av = core[0]
            n = str(op)
            if n == "BRANCH":
                return list(av[1])
            if n == "SUBPATTERN":
                return top_alternation(av[-1])
        return None

    branches = top_alternation(parsed) or [parsed]

    def optional_count(seq):
        o = [0, None]
        _emit(seq, False, None, [0], o)
        return o[0]

    out = []
    regimes = {}
    for i, b in enumerate(branches):
        picks, regime = pick_vectors(alternations(b))
        regimes[i] = regime
        for spaced in (False, True):
            for pk in picks:
              # Every optional arm on its own, present and absent. `guardrails?`
              # has to yield BOTH `guardrail` and `guardrails`, because the two
              # route differently and only the plural was ever generated. The
              # arm indices depend on WHICH alternative `pk` selected, so they
              # are counted per pick rather than once for the branch.
              counted = [0, None]
              _emit(b, spaced, pk, [0], counted)
              n_opt = min(counted[0], MAX_OPTIONAL_ARMS)
              # All present, each one absent on its own, ALL absent together,
              # and each group at its own maximum. The reviewer's three grammar
              # witnesses are the last three of those: two independent optionals
              # both absent, an alternative inside a nested optional, and the
              # top of a `{0,2}`.
              vectors = [{}]
              vectors += [{k: 0} for k in range(n_opt)]
              if n_opt > 1:
                  vectors.append({k: 0 for k in range(n_opt)})
              vectors += [{k: MAX_OPTIONAL_REPS} for k in range(n_opt)]
              for choices in vectors:
                s = _emit(b, spaced, pk, [0], [0, choices])
                if not s.strip():
                    continue
                out.append((i, s, "core"))
                # ONE newline in each whitespace position. The regex accepts
                # these because its separators are `\s+`, but a keyword is a
                # contiguous string, so routing them needs a shorter and more
                # generic keyword for every position. Reported, not asserted:
                # the trade belongs in the PR, not in a silent list edit.
                for k, ch in enumerate(s):
                    if ch == " ":
                        out.append((i, s[:k] + "\n" + s[k + 1:], "newline_split"))
    # de-duplicate while keeping order
    seen, uniq = set(), []
    for i, s, kind in out:
        if (i, s) not in seen:
            seen.add((i, s)); uniq.append((i, s, kind))
    return uniq
