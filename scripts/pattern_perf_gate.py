#!/usr/bin/env python3
"""Pattern-perf gate: time the regexes a pull request changes, base against head.

tests/test_regex_repeat_shape_lint.py is static and per rule id. It cannot see a constant-factor
jump or a shape its walker does not model. This gate is dynamic: for every pattern id that is new or
whose regex list differs between the pull request's base and head, it repeats crafted units to 50k and
100k characters (25k, 50k and 100k for a changed id) and times `re.search` of each regex to be judged, ALONE, on both trees, in one process on one
runner. Each regex gets its own units, so a heavy or slow expression cannot hide another. It fails on

  * growth: head time at 100k over head time at 50k above GROWTH_MAX (superlinear), when the head
    time at 100k is above GROWTH_FLOOR_S;
  * ratio: head time over base time at 100k above RATIO_MAX, when the head time is above
    RATIO_FLOOR_S;
  * a head run that reaches RUN_CAP_S, in the ranking pre-pass or in a measurement, and any work the
    wall-clock budget WALL_CAP_S left undone or finished after (a base run that reaches RUN_CAP_S at
    the largest size only leaves the head/base ratio unjudged; growth of the head is still judged);
  * a rule table that cannot be read on either side (missing file, missing commit, empty table,
    duplicate id, a construct the reader does not read), and a wall budget spent before the run ended,
    reading the tables included.

A short run is repeated until the sample totals about ADAPT_S (at most MAX_REPEATS) and the median
is kept; a run of ADAPT_S or more is confirmed by a second run and the lower of the two is kept,
because noise only adds time. A run near RUN_CAP_S, or with too little budget left for a second run,
is kept unconfirmed.

The engine's lead-in, window and guard bounding is NOT modelled, so a flagged id can be one the
engine already bounds; that is what tests/pattern_perf_waivers.json is for:
{id: "YYYY-MM-DD reason"}. A waived id is still printed; a waiver suppresses growth, ratio and cap
failures of its id. A waiver is a reviewed exception, visible as a diff of that file. The verdict
reads the waiver file of the BASE only: the head's file is checked for its format and never decides
a verdict, and a pull request that changes any rule cannot change the waiver file in the same pull
request (that fails), so a waiver arrives in a pull request of its own, which changes no rule, and
applies to the pull requests after it. A waived id that is timed (new or changed) and does not trip
FAILS. Waivers on ids nobody touches are not retimed.

What the gate trusts: it runs from the base branch (the workflow is .github/workflows/pattern-perf.yml,
a pull_request_target job, so the pull request cannot edit the job that judges it), it reads the rule
tables of the head by `git show` of a 40-character sha, refuses a source with an import, an unknown
call or another unsupported construct before evaluating anything, evaluates only the validated subset,
and it relies on the workflow, this script and its tests being reviewed like any other code. It is a tripwire
for the shapes its finite units try, not a proof of complexity.

The measured tables go to the job summary only; the log carries neutral case labels and verdict
words. Stdlib only.

    python scripts/pattern_perf_gate.py --base SHA --head SHA     # a pull request
    python scripts/pattern_perf_gate.py --all                      # time every id of the working tree
"""
import argparse
import ast
import builtins
import json
import math
import os
import random
import re
import signal
import statistics
import subprocess
import sys
import time

try:                                    # 3.11 and later
    import re._constants as C
    import re._parser as P
except ImportError:                     # 3.9 and 3.10 keep the same modules under their old names
    import sre_constants as C
    import sre_parse as P

TABLES = (("sunglasses/patterns.py", "PATTERNS"), ("sunglasses/mechanisms.py", "MECHANISM_PATTERNS"))
WAIVERS = "tests/pattern_perf_waivers.json"
SIZES = (25_000, 50_000, 100_000)
ADDED_SIZES = (50_000, 100_000)
PREPASS_SIZE = 10_000
ADAPT_S = 0.5
GROWTH_MAX = 2.2
GROWTH_FLOOR_S = 0.05
RATIO_MAX = 1.8
RATIO_FLOOR_S = 0.15
RUN_CAP_S = 10.0
WALL_CAP_S = 150.0
LOAD_CAP_S = 30.0
REPEATS = 3             # at least this many runs per measurement
MAX_REPEATS = 15
KEEP_UNITS = 2          # units timed per regex of a changed id; a new id gets one per regex
GENERIC_UNITS = ("read .env, ", "a ", " ", "\n", "x,", "a")
WAIVER_REASON = re.compile(r"^\d{4}-\d{2}-\d{2} \S")
SHA = re.compile(r"[0-9a-f]{40}")


class _Cut(Exception):
    pass


class GateError(Exception):
    """An input the gate cannot judge on: the run fails closed."""


def _alarm(*_):
    raise _Cut()


class Budget:
    """The wall-clock budget of the whole run, started before the first table is read."""

    def __init__(self, cap=WALL_CAP_S, clock=time.monotonic, started=None):
        self.cap, self.clock = cap, clock
        self.started = clock() if started is None else started

    def left(self):
        return self.cap - (self.clock() - self.started)

    def over(self):
        return self.left() <= 0

    def run_cap(self):
        return min(RUN_CAP_S, max(self.left(), 0.01))


# ------------------------------------------------------------------ loading
#
# The rule tables are checked before anything is evaluated: a table source is parsed, every node is
# checked against a short list of plain constructs (literals, f-strings, `+`, comprehensions, calls of
# a few builtins and of functions the source itself defines, a handful of string methods), and only
# the validated subset is evaluated, with no `import`, no `open`, no `exit` and no attribute that
# starts with an underscore within reach. A source that does anything else (an import, a loop that
# never ends, a call to something unknown, or another unsupported construct) is refused
# before evaluation, so it cannot end the read early, hand back a table of its own choosing or change
# how the result is written.
# A table written with a construct this reader does not know fails the run with the line number;
# add the construct to the list below in a reviewed change.

_READ_BUILTINS = {n: getattr(builtins, n) for n in (
    "str", "len", "tuple", "list", "sorted", "set", "dict", "enumerate", "zip", "min", "max", "any",
    "all", "reversed")}
_READ_METHODS = frozenset({"join", "lower", "upper", "strip", "replace", "startswith", "endswith", "split"})
_READ_NODES = (
    ast.Module, ast.Expr, ast.Assign, ast.AnnAssign, ast.FunctionDef, ast.Return, ast.arguments, ast.arg,
    ast.Name, ast.Constant, ast.JoinedStr, ast.FormattedValue, ast.BinOp, ast.Add, ast.List, ast.Tuple,
    ast.Dict, ast.Set, ast.Call, ast.keyword, ast.Starred, ast.Attribute, ast.GeneratorExp, ast.ListComp,
    ast.comprehension, ast.Subscript, ast.Slice, ast.Load, ast.Store, ast.IfExp, ast.Compare, ast.Eq,
    ast.NotEq, ast.In, ast.NotIn, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not)


def _unreadable(path, node, why):
    raise GateError(f"{path} line {getattr(node, 'lineno', '?')}: {why}; the gate evaluates only a "
                    "short list of plain constructs and does not accept this")


def _check_readable(tree, path):
    defined = set(_READ_BUILTINS)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            defined.add(node.name)
    for node in ast.walk(tree):
        if not isinstance(node, _READ_NODES):
            _unreadable(path, node, f"a {type(node).__name__} is not a construct it reads")
        if isinstance(node, ast.Name) and node.id.startswith("__"):
            _unreadable(path, node, f"the name {node.id} is not readable")
        if isinstance(node, ast.Attribute) and node.attr not in _READ_METHODS:
            _unreadable(path, node, f"the attribute .{node.attr} is not readable")
        if isinstance(node, ast.Call):
            f = node.func
            if not ((isinstance(f, ast.Name) and f.id in defined) or isinstance(f, ast.Attribute)):
                _unreadable(path, node, "a call of something that is not a builtin or a function of the source")
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if not all(isinstance(t, ast.Name) for t in targets):
                _unreadable(path, node, "an assignment to something that is not a plain name")
        if isinstance(node, ast.Expr) and not (isinstance(node.value, ast.Constant)
                                              and isinstance(node.value.value, str)):
            _unreadable(path, node, "a statement that is not a docstring")
        if isinstance(node, ast.FunctionDef) and node.decorator_list:
            _unreadable(path, node, "a decorated function")


def _within(seconds, what, fn):
    """fn() with SIGALRM cutting it off after `seconds`; GateError when it is cut off or already late."""
    if seconds <= 0:
        raise GateError(f"the wall budget was spent before {what}")
    use = hasattr(signal, "setitimer")
    previous = None
    if use:
        previous = signal.signal(signal.SIGALRM, _alarm)
        signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return fn()
    except _Cut:
        raise GateError(f"{what} did not finish in the time left")
    finally:
        if use:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous if previous is not None else signal.SIG_DFL)


def _read_table(source, path, table):
    """[(id, (regex, ...)), ...] of `table` in `source`, checked, then evaluated as the validated subset."""
    try:
        tree = ast.parse(source, path)
    except (SyntaxError, ValueError) as e:
        raise GateError(f"{path} does not parse ({type(e).__name__})")
    _check_readable(tree, path)
    ns = {"__builtins__": dict(_READ_BUILTINS), "__name__": "_perf_rules"}
    try:
        exec(compile(tree, path, "exec"), ns)
    except (_Cut, GateError):
        raise
    except Exception as e:                  # RecursionError, NameError, TypeError ...: not readable
        raise GateError(f"{path} could not be read ({type(e).__name__})")
    rows = ns.get(table)
    if not isinstance(rows, (list, tuple)):
        raise GateError(f"{path} has no {table} list")
    out = []
    for r in rows:
        rx = r.get("regex") or [] if isinstance(r, dict) else None
        if not (isinstance(r, dict) and isinstance(r.get("id"), str)
                and isinstance(rx, (list, tuple)) and all(isinstance(x, str) for x in rx)):
            raise GateError(f"the {table} table has an entry without a string id and a list of regex strings")
        out.append((r["id"], tuple(rx)))
    return out


def rules_from_sources(sources, budget=None):
    """{path: source text} -> {rule id: tuple of regex strings}.

    Every table must be present and non-empty, and an id may appear once across all tables: a table
    that is missing, empty or ambiguous cannot be compared, so the run fails closed. Reading takes
    its time from `budget` (the run's wall budget), at most LOAD_CAP_S per table, and a budget spent
    by the end of the reading is a failure.
    """
    out = {}
    for path, table in TABLES:
        text = sources.get(path)
        if text is None:
            raise GateError(f"{path} is not readable")
        left = LOAD_CAP_S if budget is None else min(LOAD_CAP_S, budget.left())
        rules = _within(left, f"the {table} table was read", lambda: _read_table(text, path, table))
        if not rules:
            raise GateError(f"the {table} table is empty")
        for rid, regexes in rules:
            if rid in out:
                raise GateError(f"rule id {rid} appears more than once")
            out[rid] = regexes
    if budget is not None and budget.over():
        raise GateError("the wall budget was spent reading the tables")
    return out


def git_show(repo, rev, path):
    """File text at rev, or None when the commit exists and does not have the file. A commit that
    cannot be read at all is a GateError, never an empty tree."""
    ok = subprocess.run(["git", "-C", repo, "cat-file", "-e", f"{rev}^{{commit}}"], capture_output=True)
    if ok.returncode != 0:
        raise GateError(f"commit {rev[:12]} is not in the checkout")
    has = subprocess.run(["git", "-C", repo, "cat-file", "-e", f"{rev}:{path}"], capture_output=True)
    if has.returncode != 0:
        return None
    r = subprocess.run(["git", "-C", repo, "show", f"{rev}:{path}"], capture_output=True, text=True)
    if r.returncode != 0:
        raise GateError(f"cannot read {path} at {rev[:12]}")
    return r.stdout


def changed_ids(base_rules, head_rules):
    """(changed, added): ids whose regex list differs, and ids the base does not have."""
    added = {i for i in head_rules if i not in base_rules and head_rules[i]}
    changed = {i for i in head_rules if i in base_rules and head_rules[i] != base_rules[i] and head_rules[i]}
    return changed, added


def waiver_conflict(base_rules, head_rules, text_base, text_head):
    """Problems when one pull request changes a rule and the waiver file together.

    "Changes a rule" is any difference between the two rule mappings (an added, removed or changed
    id, a list emptied, a regex moved); "changes the waiver file" is any difference in its text.
    """
    if head_rules != base_rules and text_head != text_base:
        return [f"this pull request changes a rule and also {WAIVERS}; a waiver arrives in a pull request "
                "of its own that changes no rule"]
    return []


def check_waivers(waivers, head_rules):
    problems = []
    for rid, reason in sorted(waivers.items()):
        if not isinstance(reason, str) or not WAIVER_REASON.match(reason):
            problems.append(f"waiver {rid} has no dated reason ('YYYY-MM-DD why'): {reason!r}")
        if rid not in head_rules:
            problems.append(f"waiver {rid} names an id that is not in the rules")
    return problems


# ------------------------------------------------------------------ units

_WILD_SUBS = (C.ANY, C.IN, C.NOT_LITERAL, C.CATEGORY)


def _is_wild(item):
    op, av = item
    if op in (C.MAX_REPEAT, C.MIN_REPEAT, getattr(C, "POSSESSIVE_REPEAT", None)):
        lo, hi, sub = av
        return len(sub) == 1 and sub[0][0] in _WILD_SUBS and (hi == C.MAXREPEAT or hi - lo >= 20)
    return False


def _sample(items, rnd):
    out = []
    atomic = getattr(C, "ATOMIC_GROUP", None)
    possessive = getattr(C, "POSSESSIVE_REPEAT", None)
    for op, av in items:
        if op == C.LITERAL:
            out.append(chr(av))
        elif op == C.NOT_LITERAL:
            out.append("a" if av != ord("a") else "b")
        elif op == C.ANY:
            out.append("a")
        elif op == C.IN:
            negate = any(o == C.NEGATE for o, _ in av)
            pick = ""
            for o, a in av:
                if o == C.LITERAL and not negate:
                    pick = chr(a)
                    break
                if o == C.RANGE and not negate:
                    pick = chr(a[0])
                    break
                if o == C.CATEGORY and not negate:
                    pick = {C.CATEGORY_DIGIT: "1", C.CATEGORY_SPACE: " "}.get(a, "a")
                    break
            out.append(pick or "a")
        elif op == C.CATEGORY:
            out.append({C.CATEGORY_DIGIT: "1", C.CATEGORY_SPACE: " ", C.CATEGORY_NOT_DIGIT: "a",
                        C.CATEGORY_NOT_SPACE: "a"}.get(av, "a"))
        elif op == C.BRANCH:
            out.append(_sample(rnd.choice(av[1]), rnd))
        elif op == C.SUBPATTERN:
            out.append(_sample(av[3], rnd))
        elif atomic is not None and op == atomic:
            out.append(_sample(av, rnd))
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT, possessive):
            lo, hi, sub = av
            if _is_wild((op, av)):
                n = lo + rnd.choice([0, 1])
            else:
                n = max(lo, 1) if lo else rnd.choice([0, 1])
            out.append("".join(_sample(sub, rnd) for _ in range(n)))
    return "".join(out)


def sampled_units(sources, seed=7, per_cut=2):
    """Prefixes of what a regex matches, each one stopping short of the whole match, then a space.

    Repeating a near miss makes the engine start a match at every repeat and walk to where it fails,
    which is the cost a crafted page pays; a full match would end the search at the first repeat.
    """
    rnd = random.Random(seed)
    units = []
    for src in sources:
        try:
            items = list(P.parse(src, re.IGNORECASE))
        except re.error:
            continue
        wide = [j for j, it in enumerate(items) if _is_wild(it)]
        cuts = sorted({j for w in wide for j in (w, w + 1) if 0 < j < len(items)} | {len(items) - 1}) or [len(items)]
        cuts = [j for j in cuts if j > 0] or [len(items)]
        for j in cuts:
            for _ in range(per_cut):
                u = _sample(items[:j], rnd)
                if u.strip():
                    units.append(u + " ")
    seen, out = set(), []
    for u in units + list(GENERIC_UNITS):
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


# ------------------------------------------------------------------ timing

def _text(unit, n):
    return (unit * (n // len(unit) + 1))[:n]


def time_once(rxs, text, cap=RUN_CAP_S):
    """Seconds for every regex of `rxs` to search `text`, or None when the cap cut it off."""
    use_cap = hasattr(signal, "setitimer")
    previous = None
    if use_cap:
        previous = signal.signal(signal.SIGALRM, _alarm)
        signal.setitimer(signal.ITIMER_REAL, cap)
    start = time.perf_counter()
    try:
        for rx in rxs:
            rx.search(text)
        return time.perf_counter() - start
    except _Cut:
        return None
    finally:
        if use_cap:
            signal.setitimer(signal.ITIMER_REAL, 0)
            # Put the host's handler back: a process that goes on to use SIGALRM itself (the
            # firewall's budget lane refuses to run when the handler is not the default) must
            # find it as it was.
            signal.signal(signal.SIGALRM, previous if previous is not None else signal.SIG_DFL)


def median_time(rxs, text, repeats, budget=None):
    """Seconds for one search, noise-resistant.

    A first run under ADAPT_S is followed by enough more to total about ADAPT_S (at least `repeats`
    in all, at most MAX_REPEATS) and the median is kept. A first run of ADAPT_S or more is confirmed
    by one more run and the lower of the two stands, since noise only adds time; a first run of half
    the run cap or more, or one that leaves under twice its length of the budget, stands unconfirmed.
    None means any run, a confirming one included, reached its cap; the budget shortens that cap so
    no run outlives the wall clock.
    """
    def one():
        return time_once(rxs, text, budget.run_cap() if budget else RUN_CAP_S)

    first = one()
    if first is None:
        return None
    if first >= ADAPT_S:
        if first >= RUN_CAP_S / 2 or (budget and budget.left() < 2 * first):
            return first
        second = one()
        return None if second is None else min(first, second)
    want = min(MAX_REPEATS, max(repeats, math.ceil(ADAPT_S / max(first, 1e-6))))
    runs = [first]
    while len(runs) < want and not (budget and budget.over()):
        r = one()
        if r is None:
            return None
        runs.append(r)
    return statistics.median(runs)


def compile_all(sources):
    return [re.compile(s, re.IGNORECASE) for s in sources]


def pick_units(regexes, keep, budget=None, capped=None):
    """The `keep` slowest units of the given regexes together, ranked by a pre-pass at PREPASS_SIZE.

    The gate calls this once per regex, so every expression of a rule is judged on the units that
    are slow for IT. The pre-pass stops when the budget is spent. A unit whose pre-pass run reached
    the run cap ranks first and is appended to `capped`, so the caller can fail it: the ranking alone
    would lose the fact once later, smaller measurements finish.
    """
    ranked = []
    for src in regexes:
        try:
            rx = re.compile(src, re.IGNORECASE)
        except re.error:
            continue
        for u in sampled_units([src]):
            if budget and budget.over():
                break
            t = time_once([rx], _text(u, PREPASS_SIZE), budget.run_cap() if budget else RUN_CAP_S)
            if t is None and capped is not None:
                capped.append(u)
            ranked.append((float("inf") if t is None else t, u))
    ranked.sort(key=lambda r: -r[0])
    picks = []
    for _, u in ranked:
        if u not in picks:
            picks.append(u)
    return picks[:keep]


# ------------------------------------------------------------------ verdicts

def judge(base, head, sizes, growth_floor=GROWTH_FLOOR_S, ratio_floor=RATIO_FLOOR_S):
    """base/head: {size: seconds or None}; base may be None (a new regex). Returns (growth, ratio, reasons).

    The reasons are neutral words; the numbers go to the job summary table.
    """
    reasons = []
    small, big = sizes[-2], sizes[-1]
    if any(head.get(s) is None for s in sizes):
        return None, None, ["a head run reached the run cap"]
    growth = head[big] / head[small] if head[small] > 0 else None
    if growth is not None and head[big] > growth_floor and growth > GROWTH_MAX:
        reasons.append("superlinear growth")
    ratio = None
    if base is not None:
        if base.get(big) is None:
            # The base reached the run cap and the head finished every size, so the head is faster
            # than the base: there is no jump to judge. Growth was judged above.
            return growth, None, reasons
        if base[big] > 0:
            ratio = head[big] / base[big]
            if head[big] > ratio_floor and ratio > RATIO_MAX:
                reasons.append("head/base jump")
    return growth, ratio, reasons


def gate(base_rules, head_rules, waivers_base, waivers_head, sizes=SIZES, added_sizes=ADDED_SIZES,
         repeats=REPEATS, wall_cap=WALL_CAP_S, only=None, clock=time.monotonic, started=None,
         growth_floor=GROWTH_FLOOR_S, ratio_floor=RATIO_FLOOR_S, probe_added_fully=False, budget=None):
    """Run the gate. Returns (rows, failures, notes); an empty failures list is a pass.

    One row per (regex, unit). Row ids are neutral labels `rN/uM`: regex N of the rule, unit M of
    that regex; the unit text itself is kept in the row for a local `--show-units` run only.
    """
    # The waivers of the BASE decide every verdict. The head's file is checked for its format and
    # nothing else: it takes effect, for the pull requests after it, once it is in the base.
    failures = check_waivers(waivers_head, head_rules)
    waivers = waivers_base or {}
    changed, added = changed_ids(base_rules, head_rules)
    # Every regex of a waived id that changed is timed, changed or not: "does not trip" is a
    # statement about the whole id, so it cannot rest on the changed expression alone.
    retime_all = {i for i in changed if i in waivers}
    todo = sorted(changed)
    new = sorted(added)
    if only is not None:
        todo, new = [i for i in todo if i in only], [i for i in new if i in only]
    notes = [f"changed {len(changed)}, added {len(added)}; timing {len(todo)} + {len(new)} new"]
    rows = []
    budget = budget or Budget(wall_cap, clock, started)
    not_run = []

    for rid, is_new in [(i, False) for i in todo] + [(i, True) for i in new]:
        if budget.over():
            rows.append(dict(id=rid, case="", unit="", verdict="NOT-RUN"))
            not_run.append(rid)
            continue
        head_src = head_rules[rid]
        base_src = () if is_new else base_rules.get(rid, ())
        if is_new or rid in retime_all:
            which = list(range(len(head_src)))
        else:
            which = [k for k, s in enumerate(head_src) if s not in base_src]
        light = is_new and not probe_added_fully
        use_sizes = added_sizes if light else sizes
        keep = 1 if light else KEEP_UNITS
        tripped_any = False
        for k in which:
            try:
                head_rx = compile_all([head_src[k]])
                base_rx = (compile_all([base_src[k]]) if (not is_new and k < len(base_src)
                                                          and base_src[k] != head_src[k]) else None)
            except re.error as e:
                failures.append(f"{rid} r{k}: does not compile ({e.msg})")
                continue
            capped = []
            units = pick_units([head_src[k]], keep, budget, capped)
            if capped:                      # a head run that reached the run cap is a verdict of its own
                tripped_any = True
                capped_verdict = "WAIVED" if rid in waivers else "FAIL"
                rows.append(dict(id=rid, case=f"r{k}/pre", unit=capped[0], base=None,
                                 head={PREPASS_SIZE: None}, growth=None, ratio=None, sizes=(PREPASS_SIZE,),
                                 verdict=capped_verdict, why="a head run reached the run cap"))
                if capped_verdict == "FAIL":
                    failures.append(f"{rid} r{k}/pre: a head run reached the run cap")
            if not units:                   # nothing to judge it on (the pre-pass spent the budget): not a pass
                rows.append(dict(id=rid, case=f"r{k}", unit="", verdict="NOT-RUN"))
                not_run.append(rid)
                continue
            for j, u in enumerate(units):
                case = f"r{k}/u{j}"
                if budget.over():
                    rows.append(dict(id=rid, case=case, unit=u, verdict="NOT-RUN"))
                    not_run.append(rid)
                    continue
                head_t, base_t = {}, ({} if base_rx is not None else None)
                for n in use_sizes:
                    text = _text(u, n)
                    if base_t is not None:
                        base_t[n] = median_time(base_rx, text, repeats, budget)
                    head_t[n] = median_time(head_rx, text, repeats, budget)
                if budget.over():           # a measurement cut short by the budget is not a verdict
                    rows.append(dict(id=rid, case=case, unit=u, verdict="NOT-RUN"))
                    not_run.append(rid)
                    continue
                growth, ratio, reasons = judge(base_t, head_t, use_sizes, growth_floor, ratio_floor)
                tripped = bool(reasons)
                tripped_any = tripped_any or tripped
                verdict = "ok" if not tripped else ("WAIVED" if rid in waivers else "FAIL")
                rows.append(dict(id=rid, case=case, unit=u, base=base_t, head=head_t, growth=growth,
                                 ratio=ratio, sizes=use_sizes, verdict=verdict, why="; ".join(reasons)))
                if verdict == "FAIL":
                    failures.append(f"{rid} {case}: " + "; ".join(reasons))
        if rid in waivers and which and not tripped_any and rid not in not_run:
            failures.append(f"{rid}: waived but does not trip; remove it from {WAIVERS}")
    for rid in sorted(set(not_run)):
        failures.append(f"{rid}: not run, the {budget.cap:g} s wall cap was reached first")
    if budget.over() and not not_run:       # spent while reading, preparing or finishing: never a pass
        failures.append(f"the {budget.cap:g} s wall cap was reached before the run finished")
    return rows, failures, notes


# ------------------------------------------------------------------ output

def _ms(d, n):
    v = (d or {}).get(n)
    return "-" if d is None else ("cap" if v is None else f"{v * 1000:.0f}")


def table(rows, show_units=False):
    lines = ["| id | case | base ms | head ms | growth | head/base | verdict |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        if r["verdict"] == "NOT-RUN":
            lines.append(f"| {r['id']} | {r.get('case', '')} | | | | | NOT-RUN |")
            continue
        s = r["sizes"]
        base = "/".join(_ms(r["base"], n) for n in s) if r["base"] is not None else "new"
        head = "/".join(_ms(r["head"], n) for n in s)
        growth = "-" if r["growth"] is None else f"{r['growth']:.2f}"
        ratio = "-" if r["ratio"] is None else f"{r['ratio']:.2f}"
        case = r["case"] + (" " + repr(r["unit"])[:30].replace("|", "/") if show_units else "")
        lines.append(f"| {r['id']} | {case} | {base} | {head} | {growth} | {ratio} | {r['verdict']} |")
    return "\n".join(lines)


def report(rows, failures, notes, show_units=False):
    """Write the full table to the job summary when there is one and return the log text.

    In a job the log gets the notes and the verdict words only (the table is in the summary); with no
    summary file (a local run) the log gets the table too.
    """
    head = ["## pattern-perf", "", *notes, ""]
    body = table(rows, show_units) if rows else "nothing to time"
    tail = ["", *(f"FAIL: {f}" for f in failures)] if failures else ["", "pattern-perf: pass"]
    full = "\n".join(head) + body + "\n" + "\n".join(tail) + "\n"
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary:
        return full
    with open(summary, "a", encoding="utf-8") as fh:
        fh.write(full)
    log = ["pattern-perf", *notes, *(f"FAIL: {f}" for f in failures)]
    return "\n".join(log + ([] if failures else ["pattern-perf: pass"]) + ["(measured table: job summary)"]) + "\n"


def read_waivers(text):
    if text is None:
        return {}
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{WAIVERS} must be a JSON object of id -> 'YYYY-MM-DD reason'")
    return data


def main(argv=None):
    started = time.monotonic()
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", default="")
    ap.add_argument("--head", default="")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--all", action="store_true", help="time every id of the working tree, head only")
    ap.add_argument("--wall-cap", type=float, default=WALL_CAP_S, help="seconds before the rest is NOT-RUN")
    ap.add_argument("--show-units", action="store_true", help="local runs: print the input fragments too")
    args = ap.parse_args(argv)
    budget = Budget(args.wall_cap, started=started)
    try:
        if args.all:
            sources = {p: open(os.path.join(args.repo, p), encoding="utf-8").read() for p, _ in TABLES}
            head_rules = rules_from_sources(sources, budget)
            wpath = os.path.join(args.repo, WAIVERS)
            waivers = read_waivers(open(wpath).read() if os.path.exists(wpath) else None)
            rows, failures, notes = gate({}, head_rules, waivers, waivers, wall_cap=args.wall_cap,
                                         budget=budget, probe_added_fully=True)
            print(report(rows, failures, notes, args.show_units))
            return 1 if failures else 0
        if not args.base and not args.head:
            print("pattern-perf: not a pull request, nothing to compare")
            return 0
        if not (SHA.fullmatch(args.base) and SHA.fullmatch(args.head)):
            print("pattern-perf: --base and --head must be 40-character lowercase hex shas", file=sys.stderr)
            return 2
        head_src = {p: git_show(args.repo, args.head, p) for p, _ in TABLES}
        base_src = {p: git_show(args.repo, args.base, p) for p, _ in TABLES}
        head_waiver_text = git_show(args.repo, args.head, WAIVERS)
        base_waiver_text = git_show(args.repo, args.base, WAIVERS)
        w_head = read_waivers(head_waiver_text)
        w_base = read_waivers(base_waiver_text)
        base_rules = rules_from_sources(base_src, budget)
        head_rules = rules_from_sources(head_src, budget)
        waiver_problems = waiver_conflict(base_rules, head_rules, base_waiver_text, head_waiver_text)
        rows, failures, notes = gate(base_rules, head_rules, w_base, w_head, wall_cap=args.wall_cap,
                                     budget=budget)
        failures = waiver_problems + failures
    except (GateError, ValueError, OSError) as e:
        print(f"pattern-perf: FAIL: {e}", file=sys.stderr)
        return 1
    print(report(rows, failures, notes, args.show_units))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
