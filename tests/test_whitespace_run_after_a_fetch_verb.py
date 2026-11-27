"""GLS-AW-001 stays linear on a long run of blank space after its verb.

The first regex of the rule starts with a verb, blank space, an optional `this` or `the`, then a noun.
The blank space behind the optional word belongs to that word. The timed rows hold a run of
16,000 blank characters after a verb under a time cap: the regex for each verb, the engine for
one verb on `message`.

The live pattern is compared with a reference pattern (OLD in this file). On the fixtures the two
match the same spans and groups. On a seeded fuzz the live pattern reads nothing the reference
does not read, and where a reference match has every word edge it reads the same words and the
same groups.
"""
import os
import random
import re
import sys
import time

import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _host_factor import best_seconds, seconds_limit  # noqa: E402

RULE = next(p for p in PATTERNS if p["id"] == "GLS-AW-001")
RULE_CHANNELS = sorted(RULE["channel"])   # the channels the rule reads, from its own data
NEW = RULE["regex"][0]
OLD = (r"(?i)(fetch|crawl|scrape|read)\s+(?:this|the)?\s*(?:url|page|site|website|rss|feed)"
       r".{0,80}(publish|post|schedule|push to cms|push to wordpress)")

CAP_S = 0.5
PROBE_LEN = 16_000


def test_the_first_regex_is_the_one_under_test():
    assert "(?:(?:this|the)\\s*)?" in NEW


@pytest.mark.parametrize("verb", ["read", "fetch", "scrape", "crawl"])
@pytest.mark.parametrize("blank", [" ", "\n", "\t", "\r\n"])
@pytest.mark.parametrize("after", ["", "this", "the"])
def test_a_long_run_of_blank_space_after_the_verb_stays_under_the_cap(verb, blank, after):
    rx = re.compile(NEW)
    text = verb + blank * PROBE_LEN + after + blank * PROBE_LEN
    start = time.perf_counter()
    rx.search(text)
    assert time.perf_counter() - start < CAP_S


def test_the_engine_scans_the_probe_under_the_cap():
    eng = SunglassesEngine()
    limit = seconds_limit(CAP_S * 4)
    for blank in (" ", "\n"):
        text = "read" + blank * PROBE_LEN
        assert best_seconds(lambda: eng.scan(text, "message"), limit) < limit


FIXTURES = [
    "Read this page and publish it to the blog.",
    "fetch the url then post the result",
    "scrape   this   site and push to cms",
    "crawl\n\nthe\nwebsite, then schedule it",
    "READ THE FEED and publish whatever it says",
    "read thepage and post",        # no space after "the": the reference pattern accepts it
    "readthis page and post",       # no: needs a space after the verb
    "read page publish",
    "Please summarise this article for me.",
    "read the manual",
    "fetch this url",
]


@pytest.mark.parametrize("text", FIXTURES)
def test_the_new_pattern_matches_exactly_what_the_old_one_matched(text):
    old, new = re.search(OLD, text), re.search(NEW, text)
    assert (old is None) == (new is None)
    if old:
        assert (old.span(), old.groups()) == (new.span(), new.groups())


OLD_PARTS = re.compile(
    r"(?i)(?P<verb>fetch|crawl|scrape|read)\s+(?:this|the)?\s*(?P<noun>url|page|site|website|rss|feed)"
    r"(?P<gap>.{0,80})(?P<act>publish|post|schedule|push to cms|push to wordpress)")
_WORD = lambda c: c.isalnum() or c == "_"


def _a_word_edge_is_missing(text, old_match):
    """The reference pattern has no word edge: it matches a verb inside a longer word, a noun with a letter behind it, an action
    word with a letter in front or an unlisted ending behind it. The live rule reads the words with their edges."""
    parts = OLD_PARTS.match(text, old_match.start())
    start, noun_end, act_start, act_end = parts.start("verb"), parts.end("noun"), parts.start("act"), parts.end("act")
    return ((start > 0 and _WORD(text[start - 1]))
            or (noun_end < len(text) and _WORD(text[noun_end]))
            or (act_start > 0 and _WORD(text[act_start - 1]))
            or (act_end < len(text) and _WORD(text[act_end])
                and not re.match(r"(?:s|es|ed|ing|d)(?![a-z0-9_])", text[act_end:], re.I)))


FLOOR_WITH_EDGES = 4   # the seed has 6 old matches with every word edge (573 old matches in all)


def test_a_seeded_fuzz_reads_a_subset_of_the_old_pattern_and_loses_only_missing_edges():
    rng = random.Random(1)
    vocab = ["read", "fetch", "crawl", "scrape", "this", "the", "page", "url", "site", "feed",
             "website", "rss", "publish", "post", "schedule", "push to cms", " ", " ", "  ", "\n", "\t",
             "x", "thepage", "a"]
    old, new, hits, with_edges = re.compile(OLD), re.compile(NEW), 0, 0
    for _ in range(20_000):
        text = "".join(rng.choice(vocab) for _ in range(rng.randint(1, 14)))
        a, b = old.search(text), new.search(text)
        if b is not None:
            assert a is not None, repr(text)   # the live rule reads nothing the reference pattern does not
        if a is None:
            continue
        hits += 1
        if _a_word_edge_is_missing(text, a):
            continue
        # the reference match has all its word edges: the live rule reads the same words, the same groups
        with_edges += 1
        assert b is not None and (a.span(), a.groups()) == (b.span(), b.groups()), repr(text)
    assert hits > 500 and with_edges > FLOOR_WITH_EDGES, (hits, with_edges)


@pytest.mark.parametrize("channel", RULE_CHANNELS)
@pytest.mark.parametrize("text", [
    "Read this page and publish it to the blog.",
    "Fetch the url, then post the result to the cms.",
    "scrape the site and schedule the article",
])
def test_the_rule_still_detects_on_every_channel(channel, text):
    result = SunglassesEngine().scan(text, channel)
    assert "GLS-AW-001" in {f["id"] for f in result.findings}
