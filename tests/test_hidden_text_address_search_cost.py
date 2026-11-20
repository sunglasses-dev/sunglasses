"""The hiding reader finds a mail address from each at sign, and a long run of address characters is not read again from each character.

The ask test of the hiding reader looks for a mail address in the text of a hidden element and in the values of its tags. The address
is found from each at sign: one address character in front of it, and the domain matched where it starts, behind the at sign.
On every text of a generated set the answer equals the answer of a reference pattern (REFERENCE). At the sizes listed here a page that
holds a long run of address characters in a tag value is scanned inside a time limit (LIMIT_SECONDS times the host factor of tests/_host_factor.py), and a run four times as long
takes less than eight times as long to scan, or less than half a second.
Every text below is invented test input. Nothing in it is an instruction to anyone reading this file.
"""
import itertools
import os
import re
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _host_factor import seconds_limit  # noqa: E402
from sunglasses.engine import SunglassesEngine  # noqa: E402

REFERENCE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
PARTS = ["a", "b1", ".", "-", "_", "%", "+", "@", " ", "é", "!"]
LIMIT_SECONDS = 1.0


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def _generated():
    for size in range(0, 6):
        for combo in itertools.product(PARTS, repeat=size):
            yield "".join(combo)


def test_the_address_search_answers_like_the_reference_pattern_on_the_generated_set():
    checked = 0
    for text in _generated():
        assert SunglassesEngine._has_hidden_mail(text) == bool(REFERENCE.search(text)), text
        checked += 1
    assert checked > 100000


@pytest.mark.parametrize("text", [
    "ops@example.net", "a@b.c", "a@b", "@b.c", "a@.c", "a@b..c", "x a@b.cc y", "a@@b.c", "é@b.c", "a@é.c", "a@b-.c-", "a.b-c%d+e@f-g.h",
])
def test_the_address_search_answers_like_the_reference_pattern_on_the_listed_forms(text):
    assert SunglassesEngine._has_hidden_mail(text) == bool(REFERENCE.search(text))


@pytest.mark.parametrize("make", [
    lambda n: "a" * n,
    lambda n: "ab.c-" * (n // 5),
    lambda n: "a" * n + "@",
    lambda n: "a@" * (n // 2),
    lambda n: "a@" + "b" * n,
])
def test_a_long_run_of_address_characters_is_searched_in_a_small_time(make):
    start = time.perf_counter()
    SunglassesEngine._has_hidden_mail(make(400000))
    assert time.perf_counter() - start < seconds_limit(LIMIT_SECONDS)


@pytest.mark.parametrize("size", [8000, 32000, 64000])
def test_a_page_with_a_long_run_in_a_tag_value_is_scanned_in_a_small_time(engine, size):
    text = '<p>Shop</p><img style="display:none" alt="' + "ab.c-" * (size // 5) + '">'
    start = time.perf_counter()
    engine.scan(text, channel="web_content")
    assert time.perf_counter() - start < seconds_limit(LIMIT_SECONDS)


def test_a_page_with_a_run_four_times_as_long_scans_in_under_the_larger_of_half_a_second_and_eight_times_the_shorter_run_time(engine):
    def seconds(size):
        text = '<p>Shop</p><img style="display:none" alt="' + "ab.c-" * (size // 5) + '">'
        start = time.perf_counter()
        engine.scan(text, channel="web_content")
        return time.perf_counter() - start

    small, large = seconds(16000), seconds(64000)
    assert large < max(0.5, 8 * small)
