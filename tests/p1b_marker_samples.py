"""Generate a minimal matching sample for every branch of a marker alternation.

The point is to stop hand-maintaining a keyword list that has to equal the set
of markers the regex accepts. Walk the SAME parse tree `_prefilter` walks, emit
a sample per branch, and let the suite prove every one of them routes.
"""
import re as _re
try:
    import re._parser as sre_parse
except ImportError:                                   # pragma: no cover
    import sre_parse


def _emit(node, spaced, pick=None, counter=None):
    """A minimal string matching one parsed sequence.

    `spaced` widens a zero-or-more to one repetition, which is how the tag
    spacing variants (`< / admin >`) get generated. `pick` selects the Nth
    alternative of the Nth nested alternation, so the five names inside
    `<(?:information|important|instructions|system|admin)>` are each covered
    rather than only the first one.
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
            lo, _hi, item = av
            reps = lo if lo else (1 if spaced else 0)
            out.append(_emit(item, spaced, pick, counter) * max(reps, 0))
        elif name == "SUBPATTERN":
            out.append(_emit(av[-1], spaced, pick, counter))
        elif name == "BRANCH":
            alts = av[1]
            idx = 0
            if counter is not None:
                here = counter[0]; counter[0] += 1
                if pick is not None and pick[0] == here:
                    idx = pick[1] % len(alts)
            out.append(_emit(alts[idx], spaced, pick, counter))
        elif name in ("AT", "ASSERT", "ASSERT_NOT"):
            continue
        elif name == "ATOMIC_GROUP":
            out.append(_emit(av, spaced, pick, counter))
    return "".join(out)


_SPACE = [' ']          # swapped to a newline for the third variant
MAX_NESTED_ALTS = 24   # widest nested alternation in the sibling markers


def _from_class(items):
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
        if n == "NEGATE":
            continue
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

    def nested_count(seq):
        c = [0]
        _emit(seq, False, None, c)
        return c[0]

    out = []
    for i, b in enumerate(branches):
        n_nested = nested_count(b)
        picks = [None] + [(g, k) for g in range(n_nested) for k in range(MAX_NESTED_ALTS)]
        for spaced in (False, True):
            for pk in picks:
                s = _emit(b, spaced, pk, [0])
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
