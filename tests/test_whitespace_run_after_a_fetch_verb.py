"""GLS-AW-001 stays linear on a long run of blank space after its verb.

The first regex of the rule read `(fetch|crawl|scrape|read)\\s+(?:this|the)?\\s*(?:url|page|...)`.
Two unbounded whitespace quantifiers sit side by side with an optional word between
them, so after a verb followed by N blank characters the engine tried every way of
splitting the run between the two before the noun failed: about N^2 steps from one
start. On a long enough run that blew through the cap of the lab B1 timed probe.

The rule is critical and reads `message`, so the cost was reachable from the
cheapest channel. The fix lets the second quantifier belong to the optional
word. It accepts exactly the strings the old pattern accepted.
"""
import random
import re
import time

import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

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
    for blank in (" ", "\n"):
        text = "read" + blank * PROBE_LEN
        start = time.perf_counter()
        eng.scan(text, "message")
        assert time.perf_counter() - start < CAP_S * 4


FIXTURES = [
    "Read this page and publish it to the blog.",
    "fetch the url then post the result",
    "scrape   this   site and push to cms",
    "crawl\n\nthe\nwebsite, then schedule it",
    "READ THE FEED and publish whatever it says",
    "read thepage and post",        # no space after "the": the old pattern accepted it
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


def test_a_seeded_fuzz_agrees_with_the_old_pattern():
    rng = random.Random(1)
    vocab = ["read", "fetch", "crawl", "scrape", "this", "the", "page", "url", "site", "feed",
             "website", "rss", "publish", "post", "schedule", "push to cms", " ", " ", "  ", "\n", "\t",
             "x", "thepage", "a"]
    old, new, hits = re.compile(OLD), re.compile(NEW), 0
    for _ in range(20_000):
        text = "".join(rng.choice(vocab) for _ in range(rng.randint(1, 14)))
        a, b = old.search(text), new.search(text)
        assert (a is None) == (b is None), repr(text)
        if a:
            hits += 1
            assert (a.span(), a.groups()) == (b.span(), b.groups()), repr(text)
    assert hits > 500, hits


@pytest.mark.parametrize("channel", RULE_CHANNELS)
@pytest.mark.parametrize("text", [
    "Read this page and publish it to the blog.",
    "Fetch the url, then post the result to the cms.",
    "scrape the site and schedule the article",
])
def test_the_rule_still_detects_on_every_channel(channel, text):
    result = SunglassesEngine().scan(text, channel)
    assert "GLS-AW-001" in {f["id"] for f in result.findings}
