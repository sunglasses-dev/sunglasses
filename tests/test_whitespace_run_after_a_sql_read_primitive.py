"""GLS-SQLFS-001 stays linear on a long run of blank space around its bracket.

The first regex of the rule had three places where two unbounded whitespace
quantifiers could split one run of blanks between them:

1. `\\s*(?:/\\*.*?\\*/)?\\s*\\(` after the primitive, with only an optional comment between
   the two. After a primitive and a long run of blanks with no bracket the engine tried
   every split before it gave up, so the cost grew with the square of the run. The lab B1
   timed probe is there to catch exactly that.
2. `\\(\\s*(?:BULK\\s+)?['\"]?[^'\")]*?(path)` after the bracket. `[^'\")]` takes blanks too,
   so a run after the bracket was split between `\\s*` and the lazy class the same way,
   and the cost grew with the square of the run whenever no sensitive path followed. The
   lab gate did not put a bracket in its probe at the time, so it never reached this one.
3. `BULK\\s+` followed by an optional quote group and the lazy class. The required blank
   after BULK, the blanks in front of the quote and the class all competed for one run.

The fix gives each run to one quantifier: the comment brings its own trailing blanks,
the blanks before BULK or before a quote belong to those two optional groups, and BULK
only checks that a blank follows while the quote group or the class takes the run itself.
The new pattern accepts exactly the strings the old pattern accepted, with the same
span and groups.
"""
import random
import re
import signal
import threading
import time

import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

RULE = next(p for p in PATTERNS if p["id"] == "GLS-SQLFS-001")
RULE_CHANNELS = sorted(RULE["channel"])   # the channels the rule reads, from its own data
NEW = RULE["regex"][0]
OLD = (r"""(?i)\b(?:pg_read_file|pg_read_binary_file|pg_stat_file|LOAD_FILE|OPENROWSET|OPENDATASOURCE)"""
       r"""\s*(?:/\*.*?\*/)?\s*\(\s*(?:BULK\s+)?['\"]?[^'\")]*?(/etc/(?:shadow|passwd|sudoers)|"""
       r"""/etc/(?:postgresql|mysql|nginx|ssh)/|pg_hba\.conf|/root/|/proc/self|\.ssh/|"""
       r"""\.aws/credentials|\.kube/config|id_rsa|id_ed25519|/var/(?:lib|run)/secrets|\.pem\b|"""
       r"""\.env\b|private[_-]?key)""")

CAP_S = 0.5
PROBE_LEN = 16_000
PRIMITIVES = ["pg_read_file", "pg_read_binary_file", "pg_stat_file", "LOAD_FILE", "OPENROWSET", "OPENDATASOURCE"]

_engine = None


class _Over(Exception):
    pass


def _seconds(fn, limit):
    """Run fn under a SIGALRM budget so a regression fails in `limit` seconds
    instead of hanging the suite on a pattern that is quadratic or worse.
    Returns the seconds taken; limit * 4 when the alarm cut it off."""
    if not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():
        pytest.skip("the per-probe budget needs SIGALRM on the main thread")

    def handler(signum, frame):
        raise _Over()
    old = signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, limit * 2)
    start = time.perf_counter()
    try:
        fn()
        return time.perf_counter() - start
    except _Over:
        return limit * 4
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def _shared_engine():
    global _engine
    if _engine is None:
        _engine = SunglassesEngine()
    return _engine


def test_the_first_regex_is_the_one_under_test():
    assert "(?:/\\*.*?\\*/\\s*)?\\((?:\\s*BULK(?=\\s))?(?:\\s*['\\\"])?" in NEW


@pytest.mark.parametrize("primitive", PRIMITIVES)
@pytest.mark.parametrize("blank", [" ", "\n", "\t", "\r\n"])
@pytest.mark.parametrize("shape", ["bare", "comment", "bracket", "bulk", "bulk_quote", "comment_bulk"])
def test_a_long_run_of_blank_space_after_the_primitive_stays_under_the_cap(primitive, blank, shape):
    rx = re.compile(NEW)
    tail = {
        "bare": "",
        "comment": "/* x */" + blank * PROBE_LEN,
        "bracket": "(" + blank * PROBE_LEN,
        "bulk": "(BULK" + blank * PROBE_LEN,
        "bulk_quote": "(BULK" + blank * PROBE_LEN + "'",
        "comment_bulk": "/* x */(" + blank + "BULK" + blank * PROBE_LEN + '"',
    }[shape]
    text = primitive + blank * PROBE_LEN + tail
    assert _seconds(lambda: rx.search(text), CAP_S) < CAP_S


@pytest.mark.parametrize("n", [16_000, 32_000, 64_000])
def test_the_cost_does_not_grow_with_the_square_of_the_run(n):
    rx = re.compile(NEW)
    text = "pg_read_file" + " " * n
    # A linear pattern stays far under the limit at the largest run, a quadratic one goes over it.
    assert _seconds(lambda: rx.search(text), 0.25) < 0.25


@pytest.mark.parametrize("n", [16_000, 32_000, 64_000])
@pytest.mark.parametrize("quote", ["", "'", '"'])
@pytest.mark.parametrize("comment", ["", "/* x */"])
def test_the_cost_after_bulk_does_not_grow_with_the_square_of_the_run(n, quote, comment):
    rx = re.compile(NEW)
    text = "OPENROWSET" + comment + "(BULK" + " " * n + quote
    # BULK needs a blank after it, but the run itself belongs to the quote group or the class.
    assert _seconds(lambda: rx.search(text), 0.25) < 0.25


def test_the_engine_scans_the_probe_under_the_cap():
    eng = _shared_engine()
    for blank in (" ", "\n"):
        text = "pg_read_file" + blank * PROBE_LEN
        assert _seconds(lambda: eng.scan(text, "message"), CAP_S * 4) < CAP_S * 4


FIXTURES = [
    "SELECT pg_read_file('/etc/passwd');",
    "select LOAD_FILE ( '/etc/passwd' )",
    "SELECT pg_read_file /* c */ ('/root/.ssh/id_rsa')",
    "SELECT pg_read_file/**/('id_rsa')",
    "SELECT pg_read_file /**/   /* b */ ('/etc/shadow')",      # one comment only: old and new refuse the second
    "SELECT * FROM OPENROWSET(BULK '/etc/shadow', SINGLE_CLOB) AS x",
    "pg_stat_file\n\n(\n'/etc/ssh/sshd_config')",
    "OPENDATASOURCE ( 'x', '/var/lib/secrets/token' )",
    "pg_read_binary_file(\"/home/u/.aws/credentials\")",
    "SELECT pg_read_file('/var/log/app.log');",                # benign path: no match
    "SELECT pg_read_file_x('/etc/passwd')",                    # not the primitive
    "xpg_read_file('/etc/passwd')",                            # no word boundary
    "pg_read_file /* unclosed ('/etc/passwd')",
    "LOAD_FILE",
    "load_file   (   'private_key.pem'",
    "pg_read_file(   '/etc/passwd')",
    "pg_read_file(   \"/etc/passwd\")",
    "pg_read_file(\n\t'/root/x')",
    "OPENROWSET( BULK   '/etc/shadow', SINGLE_CLOB)",
    "OPENROWSET(BULK '/etc/shadow'",
    "OPENROWSET(BULK\n'/etc/shadow'",
    "OPENROWSET(BULKX '/etc/shadow'",
    "pg_read_file(   x/etc/passwd",
    "pg_read_file(  ' /etc/passwd",
    "pg_read_file(  'a' /etc/passwd",
    "pg_read_file(   )/etc/passwd",
    "pg_read_file(/* c */ '/etc/passwd')",
    "OPENROWSET(BULK   \"/etc/passwd\"",
    "OPENROWSET(BULK\t\t'/root/x'",
    "OPENROWSET( BULK   x   '/etc/shadow'",
    "OPENROWSET(BULK   /etc/shadow",
    "OPENROWSET(BULK   )   /etc/shadow",
    "OPENROWSET(bulk\n\n\"id_rsa\"",
    "OPENROWSET(BULK'/etc/shadow'",
    "OPENROWSET(BULK",
    "OPENROWSET(BULK ",
    "OPENROWSET(BULK   '   /etc/shadow'",
    "OPENROWSET(BULK   ' x ' /root/",
    "OPENROWSET /**/ (  BULK  \"  .env\"",
]


@pytest.mark.parametrize("text", FIXTURES)
def test_the_new_pattern_matches_exactly_what_the_old_one_matched(text):
    old, new = re.search(OLD, text), re.search(NEW, text)
    assert (old is None) == (new is None)
    if old:
        assert (old.span(), old.groups()) == (new.span(), new.groups())


def test_a_seeded_fuzz_agrees_with_the_old_pattern():
    rng = random.Random(1)
    vocab = ["pg_read_file", "LOAD_FILE", "OPENROWSET", "pg_stat_file", "(", "(", ")", "'", '"', "BULK", "bulk ",
             "/*", "*/", "/**/", "/* x */", " ", " ", "  ", "\n", "\t", "BULK  ", "BULK\n", "/etc/passwd", "/etc/ssh/", "id_rsa",
             ".env", "private_key", "x", "/", "*", "a.pem"]
    old, new, hits = re.compile(OLD), re.compile(NEW), 0
    for _ in range(30_000):
        text = "".join(rng.choice(vocab) for _ in range(rng.randint(1, 16)))
        a, b = old.search(text), new.search(text)
        assert (a is None) == (b is None), repr(text)
        if a:
            hits += 1
            assert (a.span(), a.groups()) == (b.span(), b.groups()), repr(text)
    assert hits > 300, hits


@pytest.mark.parametrize("channel", RULE_CHANNELS)
@pytest.mark.parametrize("text", [
    "SELECT pg_read_file('/etc/passwd');",
    "select LOAD_FILE ( '/etc/passwd' )",
    "SELECT pg_read_file /* c */ ('/root/.ssh/id_rsa')",
])
def test_the_rule_still_detects_on_every_channel(channel, text):
    result = _shared_engine().scan(text, channel)
    assert "GLS-SQLFS-001" in {f["id"] for f in result.findings}
