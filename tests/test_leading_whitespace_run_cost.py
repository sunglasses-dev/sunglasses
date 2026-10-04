r"""The eighteen rules that begin with a run of whitespace and then test the whole text.

Eighteen rules (GLS-SE-010, GLS-MR-003, 004, 015, 035, 036, 039, 040, 041, 047, 049 and 056,
GLS-AW-671, 676, 679, 683, 685 and 712) are one regex each of the shape
`(?is)^\s*(?!.*NEG)(?=.*POS)...(?=.*POS).*$`. When a text starts with n whitespace characters
and a lookahead then fails, the search gave back one character of the run at a time and ran
the lookaheads over the whole text again at each shorter prefix, so the time on a text with a
long run of whitespace in front grew with n times the length of the text: 16,000 leading
spaces took a little over a second per rule on the test machine.

Every lookahead of these rules begins with a character that is not whitespace, so what it finds
is the same for each prefix inside the run, and a match covers the whole text whatever the run
took. The head is now `^(?:(?=(\s*))\1)`: the lookahead reads the whole run once, and the group
consumes exactly that run. `re` does not give back what a lookahead matched, so the search never
tries a shorter prefix. The `(?:` keeps the start of the regex from reading as `^` followed by
a lookahead, which the engine would move to its windowed mode; the CLASSIFICATION tests pin that
the rules stay in the plain mode with the same required words. The group is the first and only
capture group of each rule and is read by nothing but the backreference.

A match starts and ends where it did before, and the first 50 characters of the match are the
finding's matched_text, so the SPAN tests compare both with the old head on one text per rule
with leading runs of several kinds and lengths. The old regex is built from the current one by
putting the old head back, so the comparison cannot drift from the rule. The words of the rules
are not changed.

Known gap. Only a run at the start of the text is read in one step; the rest of each regex,
after the head, is not changed. The cost tests time each rule's own regex and not a scan, so
they say nothing about other rules that read the same text.

On main the two head-form tests and the five cost tests fail. The span, classification and scan
tests pass on main and on this change.
"""
import copy
import re
import time

import pytest

from sunglasses import _prefilter
from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

OLD_HEAD = r"(?is)^\s*"
NEW_HEAD = r"(?is)^(?:(?=(\s*))\1)"
LIMIT_SECONDS = 0.25

# One text that each rule matches, taken from the rule's own lookaheads.
POSITIVE = {
    "GLS-SE-010": "commanda tool sandboxdisabled true host execution run",
    "GLS-MR-003": "differential-privacy adjacent bound     mismatched accept consumer",
    "GLS-MR-004": "replaying graph field fraud reuse without",
    "GLS-MR-015": "MCP Inspector malicious browser DNS rebinding no authentication starts MCP command",
    "GLS-MR-035": "instruction-focused tun cybersecurity QA parametric knowledge degrad hide retrieved context capable",
    "GLS-MR-036": "Streamable HTTP invalid authorization value unverified  principal replaced allows  resource",
    "GLS-MR-039": "training data quote clinical",
    "GLS-MR-040": "safety guarantee stale send_archive treat safe",
    "GLS-MR-041": "model-serving \"best_of\"value of 11111 cpu denial of service",
    "GLS-MR-047": "expert-routing execution telemetry harmful camouflage safety monitor fail to detect",
    "GLS-MR-049": "ThreatForest similarity mapping collision close finding",
    "GLS-MR-056": "model context protocol MCP endpoint unauthenticated remote     request auto-mint trigger     operation",
    "GLS-AW-671": "self-check heterogeneous signal raw evidence suppress complete",
    "GLS-AW-676": "remediat unsafe disappeared omitted  escape accepted",
    "GLS-AW-679": "rendered branch trace agent golden authoriz unbound trace",
    "GLS-AW-683": "exact generation-time UI authentic no artifact SHA usea  proof",
    "GLS-AW-685": "RAG discriminativea  probea set of unordered deduce vendor inversion probe",
    "GLS-AW-712": "generate-check-fix four principles satisfied ignore runtime feedback trusted",
}
IDS = sorted(POSITIVE)


def _source(rule_id):
    rule = next(p for p in PATTERNS if p["id"] == rule_id)
    assert len(rule["regex"]) == 1
    return rule["regex"][0]


def _old(rule_id):
    return re.compile(_source(rule_id).replace(NEW_HEAD, OLD_HEAD, 1))


def _requirement(rx_source):
    return tuple(sorted(tuple(sorted(c)) for c in _prefilter.requirement(rx_source)))


def test_the_eighteen_rules_start_with_the_new_head():
    assert len(IDS) == 18
    for rule_id in IDS:
        source = _source(rule_id)
        assert source.startswith(NEW_HEAD + "(?!.*"), rule_id
        assert source.count(NEW_HEAD) == 1 and OLD_HEAD not in source, rule_id
        rx = re.compile(source)
        assert rx.groups == 1, rule_id
        assert not re.search(r"\\[1-9]", source.replace(NEW_HEAD, "", 1)), rule_id


def test_the_old_head_is_gone_from_every_other_rule_that_has_the_shape():
    for rule in PATTERNS:
        regex = rule.get("regex") or []
        for source in [regex] if isinstance(regex, str) else regex:
            if source.startswith(OLD_HEAD + "(?!"):
                pytest.fail(f"{rule['id']} still starts with the old head")


def test_every_rule_matches_its_own_text():
    for rule_id in IDS:
        assert re.compile(_source(rule_id)).search(POSITIVE[rule_id]), rule_id


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def test_the_rules_stay_in_the_plain_mode_with_the_same_required_words(engine):
    seen = set()
    for pattern, compiled in engine._regex_patterns:
        if pattern["id"] not in IDS:
            continue
        seen.add(pattern["id"])
        assert len(compiled) == 1
        mode, rx, guards = compiled[0]
        assert mode == "plain" and guards is None, pattern["id"]
        old_source = rx.pattern.replace(NEW_HEAD, OLD_HEAD, 1)
        assert _requirement(rx.pattern) == _requirement(old_source), pattern["id"]
        assert tuple(sorted(tuple(sorted(c)) for c in engine._regex_requirement[id(rx)])) == _requirement(old_source)
    assert seen == set(IDS)


# The scan, not only the regex: decision, finding ids and matched text of an engine with the
# old head put back and of the engine as it is, on each channel of each rule.
def _old_engine():
    patterns = copy.deepcopy(PATTERNS)
    for p in patterns:
        if p["id"] in IDS:
            p["regex"] = [r.replace(NEW_HEAD, OLD_HEAD, 1) for r in p["regex"]]
    return SunglassesEngine(patterns=patterns)


def _summary(result):
    return (
        result.decision,
        sorted(
            (f["id"] if isinstance(f, dict) else f.id,
             (f.get("matched_text") if isinstance(f, dict) else getattr(f, "matched_text", None)))
            for f in result.findings
        ),
    )


def test_scan_agrees_with_the_old_head(engine):
    old = _old_engine()
    channels = {p["id"]: p["channel"] for p in PATTERNS if p["id"] in IDS}
    fired = 0
    for rule_id in IDS:
        for run in ["", " ", " " * 100, "\n" * 40, "\r\n" * 20, "\t \n" * 10]:
            for body in (POSITIVE[rule_id], "hello " + POSITIVE[rule_id] + " unit test", "hello"):
                for channel in channels[rule_id]:
                    a = _summary(old.scan(run + body, channel=channel))
                    b = _summary(engine.scan(run + body, channel=channel))
                    assert a == b, (rule_id, channel, repr(run[:10]))
                    fired += any(i == rule_id for i, _ in a[1])
    assert fired > 50


RUNS = ["", " ", "  ", " " * 5, " " * 100, "\n", "\n\n\n", "\r\n" * 4, "\t" * 7, " \n\t \r\n", "\x0b\x0c ", " " * 700]
WRAPPERS = [
    ("", ""),
    ("", " unit test"),
    ("", " documentation"),
    ("x ", ""),
    ("", "\n" + "tail text"),
]


@pytest.mark.parametrize("rule_id", IDS)
def test_span_matches_the_old_head(rule_id):
    new, old = re.compile(_source(rule_id)), _old(rule_id)
    matched = 0
    for run in RUNS:
        for front, back in WRAPPERS:
            for body in (POSITIVE[rule_id], POSITIVE[rule_id].upper(), "hello", ""):
                text = run + front + body + back
                a, b = old.search(text), new.search(text)
                assert (a is None) == (b is None), repr(text[:60])
                if a is None:
                    continue
                matched += 1
                assert (a.start(), a.end(), a.group(0)[:50]) == (b.start(), b.end(), b.group(0)[:50]), repr(text[:60])
    assert matched > 20


# Cost, with each rule's own regex. The text is a run of 16,000 whitespace characters and then a
# body the lookaheads cannot satisfy, so the old head tried every prefix of the run. A text
# that matches returns at once and measures nothing.
LONG = 16000
SHAPES = {
    "spaces": " " * LONG,
    "line breaks": "\n" * LONG,
    "CRLF": "\r\n" * (LONG // 2),
    "tabs": "\t" * LONG,
    "mixed": " \n\t" * (LONG // 3),
}


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_a_long_leading_run_is_cheap_for_each_rule(shape):
    text = SHAPES[shape] + "plain words that no rule is waiting for"
    for rule_id in IDS:
        rx = re.compile(_source(rule_id))
        start = time.perf_counter()
        assert rx.search(text) is None
        assert time.perf_counter() - start < LIMIT_SECONDS, rule_id
