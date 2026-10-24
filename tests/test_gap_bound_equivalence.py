"""Regression coverage for the bounded gap in GLS-AB-001, GLS-CI-004, GLS-PT-001 and GLS-CI-005.

The covered regex entries join two parts with a gap of at most GAP characters (code points). Entries
written with `.` stop at LF (so they stop at LF and at the LF of a CRLF) but accept a bare CR: for
them the gap can hold CR and is bounded in total length. The GLS-CI-005 entry is written with `[^)]`,
which takes every line break: its gap may span lines, and its bound counts the line breaks, so a call
whose arguments run past GAP characters over several lines is not reported (pinned below for LF,
CRLF and CR).

What these tests pin:

1. The shipped form and an unbounded-gap reference agree on a fixed table and on a seeded set of
   random strings (every gap in the table and the random strings is shorter than GAP).
2. The bound sits exactly at GAP: a gap of GAP characters matches, a gap of GAP + 1 does not.
3. The engine fires on the usual shape of each rule and stays quiet on a near miss, except for the
   third GLS-AB-001 entry (the cache-key one), whose near-miss text the rule's other entry reports.
4. The compiled patterns keep the bounded form (an implementation pin, not a performance check).
"""

import random
import re

import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

GAP = 1000

# (rule id, regex index, earlier form, new form)
CASES = [
    ("GLS-AB-001", 1,
     r"(?:hash|md5|sha)\s*\(.*(?:token|key)\s*\)\s*\[\s*:\s*\d+\s*\]",
     r"(?:hash|md5|sha)\s*\(.{0,1000}(?:token|key)\s*\)\s*\[\s*:\s*\d+\s*\]"),
    ("GLS-AB-001", 2,
     r"cache_key\s*=.*(?:token|key)\s*\[\s*:\s*\d+\s*\]",
     r"cache_key\s*=.{0,1000}(?:token|key)\s*\[\s*:\s*\d+\s*\]"),
    ("GLS-CI-004", 3,
     r"subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True",
     r"subprocess\.(?:call|run|Popen)\s*\(.{0,1000}shell\s*=\s*True"),
    ("GLS-PT-001", 1,
     r"(?:load_prompt|load_template|read_file|open)\s*\(.*(?:\.\./|\.\.\\)",
     r"(?:load_prompt|load_template|read_file|open)\s*\(.{0,1000}(?:\.\./|\.\.\\)"),
    ("GLS-PT-001", 2,
     r"os\.path\.join\s*\(.*(?:user_input|request\.|params\[|args\[)",
     r"os\.path\.join\s*\(.{0,1000}(?:user_input|request\.|params\[|args\[)"),
    ("GLS-CI-005", 0,
     r"(?i)os\.system\(|subprocess\.(?:Popen|run|call)\([^)]*shell\s*=\s*True|bash\s+-i|/dev/tcp/|nc\s+-e|reverse shell",
     r"(?i)os\.system\(|subprocess\.(?:Popen|run|call)\([^)]{0,1000}shell\s*=\s*True|bash\s+-i|/dev/tcp/|nc\s+-e|reverse shell"),
]

# One hostile-looking line per case: the two parts with a short gap between them.
HITS = {
    ("GLS-AB-001", 1): "digest = sha(user.session_token)[:8]",
    ("GLS-AB-001", 2): "cache_key = prefix + api_token[:10]",
    ("GLS-CI-004", 3): "subprocess.run(cmd, check=True, shell=True)",
    ("GLS-PT-001", 1): "open(base + '../../etc/passwd')",
    ("GLS-PT-001", 2): "os.path.join(root, user_input)",
    ("GLS-CI-005", 0): "subprocess.Popen(cmd, shell=True)",
}

# Pieces the random strings are built from: the parts of every case, near misses, and filler.
WORDS = ["hash(", "md5 (", "sha(", "cache_key =", "cache_key=", "token", "key", ")", "[:8]", "[ : 12 ]", "[:x]",
         "subprocess.run(", "subprocess.call (", "Popen(", "shell=True", "shell = True", "shell=False",
         "open(", "load_prompt (", "read_file(", "../", "..\\", "..", "os.path.join(", "user_input",
         "request.", "params[", "args[", "os.system(", "bash -i", "nc -e", "reverse shell", "x", "y", " ",
         "\n", "\t", "(", "a", "z", "=", "sha", "hash", "TOKEN", "Shell=true",
         "token)", "key)[:8]", "token[:4]", "key [ :2 ]", "sha(token", "cache_key = k"]

TABLE = [
    "", "sha(", "sha(token)[:4]", "sha(token)[:4", "sha(x token) [ : 12 ]", "SHA( KEY )[:1]", "hash(key)\n[:3]",
    "md5(token)[:]", "cache_key=token[:9]", "cache_key = a\nb token[:9]", "cache_key = key [ :2 ]",
    "subprocess.run(x, shell=True)", "subprocess.run(x)\nshell=True", "subprocess.call(shell = True)",
    "subprocess.Popen(a(b), shell=True)", "subprocess.Popen(a(b)), shell=True", "subprocess.run(shell=False)",
    "open(../)", "open(..\\)", "open('a/../b')", "read_file(x)\n../", "load_prompt(a, '../../x')",
    "os.path.join(a, request.args)", "os.path.join(a, b)", "os.path.join(\nuser_input)", "OS.PATH.JOIN(PARAMS[1])",
    "os.system(", "bash -i", "nc -e", "reverse shell", "subprocess.run(a) shell=True",
]


def _rule_regexes(rid):
    (rule,) = [r for r in PATTERNS if r["id"] == rid]
    return rule["regex"], rule["channel"]


def _new_rx(rid, idx):
    regexes, _channels = _rule_regexes(rid)
    return regexes[idx]


def _compile(pattern):
    return re.compile(pattern, re.IGNORECASE)


@pytest.mark.parametrize("rid,idx,old,new", CASES)
def test_the_rule_carries_the_new_form(rid, idx, old, new):
    assert _new_rx(rid, idx) == new


@pytest.mark.parametrize("rid,idx,old,new", CASES)
def test_new_and_earlier_form_agree_on_a_table(rid, idx, old, new):
    old_rx, new_rx = _compile(old), _compile(new)
    for text in TABLE + [HITS[(rid, idx)]]:
        a, b = old_rx.search(text), new_rx.search(text)
        assert bool(a) == bool(b), repr(text)
        if a:
            assert a.start() == b.start(), repr(text)
            assert a.group(0)[:50] == b.group(0)[:50], repr(text)


@pytest.mark.parametrize("rid,idx,old,new", CASES)
def test_new_and_earlier_form_agree_on_random_strings(rid, idx, old, new):
    old_rx, new_rx = _compile(old), _compile(new)
    rng = random.Random(224 + idx)
    positives = 0
    for _ in range(20000):
        text = "".join(rng.choice(WORDS) + rng.choice(["", " ", "\n"]) for _ in range(rng.randint(0, 14)))
        a, b = old_rx.search(text), new_rx.search(text)
        positives += bool(a)
        assert bool(a) == bool(b), repr(text)
        if a:
            assert a.start() == b.start(), repr(text)
            assert a.group(0)[:50] == b.group(0)[:50], repr(text)
    assert positives > 100, (rid, idx, positives)


def _split(hit):
    """Split the hit line into the text before the gap and the text after it."""
    head = {
        ("GLS-AB-001", 1): ("sha(", "token)[:8]"),
        ("GLS-AB-001", 2): ("cache_key =", "token[:10]"),
        ("GLS-CI-004", 3): ("subprocess.run(", "shell=True"),
        ("GLS-PT-001", 1): ("open(", "../x"),
        ("GLS-PT-001", 2): ("os.path.join(", "user_input"),
        ("GLS-CI-005", 0): ("subprocess.Popen(", "shell=True"),
    }
    return head[hit]


@pytest.mark.parametrize("rid,idx,old,new", CASES)
def test_the_only_difference_sits_exactly_at_the_bound(rid, idx, old, new):
    before, after = _split((rid, idx))
    old_rx, new_rx = _compile(old), _compile(new)
    # The filler has no `)` and no newline, so it is legal for the earlier `[^)]*` form too.
    at_bound = before + "q" * GAP + after
    past_bound = before + "q" * (GAP + 1) + after
    assert old_rx.search(at_bound) and new_rx.search(at_bound)
    assert old_rx.search(past_bound) and not new_rx.search(past_bound)


MULTILINE = [c for c in CASES if c[0] == "GLS-CI-005"]
BREAKS = ["\n", "\r\n", "\r"]


def _gap(n, brk):
    """n characters (line breaks counted) of lines that hold no `)`, joined by `brk`."""
    unit = "q" * 9 + brk
    return (unit * (n // len(unit) + 1))[:n]


@pytest.mark.parametrize("brk", BREAKS)
@pytest.mark.parametrize("rid,idx,old,new", MULTILINE)
def test_a_gap_that_spans_lines_is_bounded_by_its_total_length_line_breaks_included(rid, idx, old, new, brk):
    old_rx, new_rx = _compile(old), _compile(new)
    before, after = _split((rid, idx))
    for n, expect_new in ((GAP, True), (GAP + 1, False), (GAP + 5000, False), (200, True)):
        text = before + _gap(n, brk) + after
        assert brk in text[len(before):len(before) + n]
        assert old_rx.search(text), n                      # the earlier form reports every one of these
        assert bool(new_rx.search(text)) is expect_new, (n, repr(brk))


@pytest.mark.parametrize("brk", BREAKS)
@pytest.mark.parametrize("rid,idx,old,new", MULTILINE)
def test_the_engine_follows_the_same_multiline_bound(rid, idx, old, new, brk):
    _regexes, channels = _rule_regexes(rid)
    engine = SunglassesEngine()
    before, after = _split((rid, idx))
    for n, expect in ((GAP, True), (GAP + 1, False)):
        text = before + _gap(n, brk) + after
        for channel in channels:
            found = {f["id"] for f in engine.scan(text, channel=channel).findings}
            assert (rid in found) is expect, (channel, n, repr(brk))


DOT_CASES = [c for c in CASES if c[0] != "GLS-CI-005"]


@pytest.mark.parametrize("rid,idx,old,new", DOT_CASES)
def test_the_dot_gap_entries_stop_at_lf_and_crlf_in_both_forms(rid, idx, old, new):
    old_rx, new_rx = _compile(old), _compile(new)
    before, after = _split((rid, idx))
    for brk in BREAKS[:2]:
        text = before + "q" * 20 + brk + "q" * 20 + after
        assert not old_rx.search(text) and not new_rx.search(text), repr(brk)


@pytest.mark.parametrize("rid,idx,old,new", DOT_CASES)
def test_the_dot_gap_entries_accept_a_bare_cr_and_bound_the_total_length(rid, idx, old, new):
    old_rx, new_rx = _compile(old), _compile(new)
    before, after = _split((rid, idx))
    for n, expect_new in ((GAP, True), (GAP + 1, False), (GAP + 5000, False), (200, True)):
        gap = _gap(n, "\r").replace(")", "q")      # no `)` so the earlier `.*` form sees the same text
        text = before + gap + after
        assert "\r" in gap
        assert old_rx.search(text), n                       # the earlier form reports every one of these
        assert bool(new_rx.search(text)) is expect_new, n


@pytest.mark.parametrize("rid,idx,old,new", CASES)
def test_the_engine_still_fires_on_the_usual_shape_and_not_on_a_near_miss(rid, idx, old, new):
    _regexes, channels = _rule_regexes(rid)
    engine = SunglassesEngine()
    hit = HITS[(rid, idx)]
    for channel in channels:
        found = {f["id"] for f in engine.scan(hit, channel=channel).findings}
        assert rid in found, (channel, hit)
    before, after = _split((rid, idx))
    near_miss = before + "q" * (GAP + 1) + after
    for channel in channels:
        found = {f["id"] for f in engine.scan(near_miss, channel=channel).findings}
        # AB-001's first regex fires on the `token[:10]` tail alone, so that near miss still fires.
        if (rid, idx) != ("GLS-AB-001", 2):
            assert rid not in found, channel


@pytest.mark.parametrize("rid,idx,old,new", CASES)
def test_the_compiled_regex_keeps_the_bounded_form(rid, idx, old, new):
    pattern = _new_rx(rid, idx)
    assert "{0,%d}" % GAP in pattern
    assert ".*" not in pattern and "[^)]*" not in pattern
