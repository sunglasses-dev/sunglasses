"""A scan reports the same thing with or without the optional pyahocorasick extension.

The engine can look for its keywords with an Aho-Corasick automaton (when the
extension is installed) or with plain string search (when it is not). The two used
to pick a rule's first keyword hit differently, so the excerpt and the order of the
findings could differ between a machine with the extension and one without, for the
same input. Both now report where each keyword first stands and take the hits in one
order, (start, end, keyword).

The corpus is the quickstart string, the benchmark attacks and the real-world false
positive documents. Each run is a fresh interpreter so the choice of path is not
undone by an import cache. Set SUNGLASSES_REQUIRE_FAST=1 (the CI leg that installs
the extension does) and a missing extension fails instead of skipping.
"""
import glob
import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CHILD = r'''
import glob, json, os, sys
mode, root = sys.argv[1], sys.argv[2]
if mode == "without":
    sys.modules["ahocorasick"] = None
sys.path.insert(0, root)
import sunglasses.engine as E
eng = E.SunglassesEngine()
if mode == "reversed":
    eng._keyword_to_patterns = dict(reversed(list(eng._keyword_to_patterns.items())))
texts = [("quickstart", "some text to check")]
attacks = json.load(open(os.path.join(root, "tests", "benchmark", "attacks.json")))["attacks"]
texts += [("attack:%d" % i, a["text"]) for i, a in enumerate(attacks)]
for p in sorted(glob.glob(os.path.join(root, "tests", "fp_real_world_corpus", "*.md"))):
    texts.append(("doc:" + os.path.basename(p), open(p, errors="ignore").read()))
results = {}
for name, text in texts:
    r = eng.scan(text)
    results[name] = {"decision": r.decision, "severity": r.severity,
                     "findings": json.loads(json.dumps(r.findings, sort_keys=True, default=str))}
print(json.dumps({"extension_in_use": E.HAS_AHOCORASICK and eng._automaton is not None,
                  "texts": len(texts), "results": results}, sort_keys=True))
'''


def _run(mode):
    out = subprocess.run([sys.executable, "-c", CHILD, mode, ROOT], capture_output=True,
                         text=True, timeout=600, cwd=ROOT)
    assert out.returncode == 0, out.stderr[-2000:]
    return json.loads(out.stdout)


def _have_extension():
    return importlib.util.find_spec("ahocorasick") is not None


def test_the_corpus_is_the_size_the_comparison_assumes():
    plain = _run("without")
    assert plain["extension_in_use"] is False
    assert plain["texts"] > 100
    assert sum(len(v["findings"]) for v in plain["results"].values()) > 50


def test_findings_do_not_depend_on_the_order_keywords_are_stored_in():
    forward = _run("without")
    backward = _run("reversed")
    assert json.dumps(forward["results"], sort_keys=True) == json.dumps(backward["results"], sort_keys=True)


def test_findings_are_byte_identical_with_and_without_the_extension():
    if not _have_extension():
        if os.environ.get("SUNGLASSES_REQUIRE_FAST") == "1":
            pytest.fail("SUNGLASSES_REQUIRE_FAST=1 but the pyahocorasick extension is not installed")
        pytest.skip("pyahocorasick is not installed")
    fast = _run("with")
    plain = _run("without")
    assert fast["extension_in_use"] is True
    assert plain["extension_in_use"] is False
    assert fast["texts"] == plain["texts"]
    assert json.dumps(fast["results"], sort_keys=True) == json.dumps(plain["results"], sort_keys=True)


# ---------------------------------------------------------------- the order itself
# Equality between the two searches cannot show the order is the intended one: both use
# the same sort, so a wrong key passes it. These cases state the order and the excerpt.

def _engine(rules, fast):
    from sunglasses.engine import SunglassesEngine
    patterns = [{"id": rid, "severity": "high", "category": "prompt_injection",
                 "description": "order probe", "channel": ["message"], "keywords": kws}
                for rid, kws in rules]
    eng = SunglassesEngine(patterns=patterns, mechanisms=False, validators=False)
    if not fast:
        eng._automaton = None
    elif eng._automaton is None:
        pytest.skip("pyahocorasick is not installed")
    return eng


def _paths():
    return [pytest.param(False, id="plain"), pytest.param(True, id="extension")]


@pytest.mark.parametrize("fast", _paths())
def test_a_rule_reports_the_keyword_that_stands_first_not_the_one_listed_first(fast):
    eng = _engine([("R-1", ["alpha", "beta"])], fast)
    finding = eng.scan("beta comes first and alpha after it").findings[0]
    assert finding["matched_text"].startswith("beta")


@pytest.mark.parametrize("fast", _paths())
def test_findings_follow_where_their_keywords_stand_not_their_spelling_or_listing(fast):
    eng = _engine([("R-A", ["alpha"]), ("R-Z", ["zeta"])], fast)
    assert [f["id"] for f in eng.scan("zeta is named before alpha here").findings] == ["R-Z", "R-A"]
    assert [f["id"] for f in eng.scan("alpha is named before zeta here").findings] == ["R-A", "R-Z"]


@pytest.mark.parametrize("fast", _paths())
def test_a_hit_that_starts_earlier_comes_first_even_when_it_ends_later(fast):
    eng = _engine([("R-LONG", ["zulu yankee"]), ("R-INNER", ["yankee"])], fast)
    assert [f["id"] for f in eng.scan("zulu yankee").findings] == ["R-LONG", "R-INNER"]
    # The inner hit also ends first, so ordering by end would put it ahead of the longer one.
    eng = _engine([("R-LONG", ["zulu yankee xray"]), ("R-INNER", ["yankee"])], fast)
    assert [f["id"] for f in eng.scan("zulu yankee xray").findings] == ["R-LONG", "R-INNER"]


@pytest.mark.parametrize("fast", _paths())
def test_of_two_hits_that_start_together_the_shorter_comes_first(fast):
    eng = _engine([("R-LONG", ["xray yankee"]), ("R-SHORT", ["xray"])], fast)
    assert [f["id"] for f in eng.scan("xray yankee").findings] == ["R-SHORT", "R-LONG"]


@pytest.mark.parametrize("fast", _paths())
def test_a_keyword_cut_short_by_a_longer_word_does_not_claim_the_rule(fast):
    eng = _engine([("R-1", ["alpha", "beta"])], fast)
    finding = eng.scan("alphabet first, then a lone beta, then alpha").findings[0]
    assert "lone beta" in finding["matched_text"]


# ----------------------------------------------- a negation built by decoding never downgrades
# A rule's finding starts at its first keyword hit. A decoded negation ("do not alpha" written
# in ROT13) must not lower it whichever of the rule's keywords the search meets first, so the
# decision cannot depend on the order the rule lists them in, or on the extension. These
# state the decision and severity themselves.

LISTINGS = [pytest.param(["alpha", "beta"], id="alpha-first"),
            pytest.param(["beta", "alpha"], id="beta-first")]


def _decision(rule_keywords, text, fast):
    result = _engine([("R-1", rule_keywords)], fast).scan(text)
    return result.decision, result.severity


@pytest.mark.parametrize("fast", _paths())
@pytest.mark.parametrize("keywords", LISTINGS)
def test_an_encoded_negation_beside_a_plain_one_does_not_lower_the_rule(keywords, fast):
    for text in ("do not alpha. qb abg orgn",      # plain "do not alpha", ROT13 "do not beta"
                 "do not beta. qb abg nycun",      # plain "do not beta", ROT13 "do not alpha"
                 'do not beta. Rknzcyr: "nycun"',  # ROT13 of: Example: "alpha"
                 "do not alpha. Rknzcyr: \"orgn\""):
        assert _decision(keywords, text, fast) == ("block", "high"), text


@pytest.mark.parametrize("fast", _paths())
@pytest.mark.parametrize("keywords", LISTINGS)
def test_plain_negation_keeps_the_decision_it_had(keywords, fast):
    assert _decision(keywords, "do not alpha", fast) == ("allow_redacted", "review")
    assert _decision(keywords, "do not beta", fast) == ("allow_redacted", "review")
    # A second keyword that stands on its own is live.
    assert _decision(keywords, "do not alpha. beta", fast) == ("block", "high")
    assert _decision(keywords, "do not beta. alpha", fast) == ("block", "high")
    assert _decision(keywords, "never alpha. beta", fast) == ("block", "high")
    # The same keyword plain and encoded, both negated, is unchanged: one finding, lowered.
    assert _decision(keywords, "do not alpha. qb abg nycun", fast) == ("allow_redacted", "review")
    assert _decision(keywords, "do not beta. qb abg orgn", fast) == ("allow_redacted", "review")


@pytest.mark.parametrize("fast", _paths())
@pytest.mark.parametrize("keywords", [["beta", "iota"], ["iota", "beta"],
                                      ["beta", "ignore previous instructions"],
                                      ["ignore previous instructions", "beta"]])
def test_a_plain_negation_before_a_look_alike_spelling_keeps_the_decision_it_had(keywords, fast):
    """`lota` and `lgnore` read as keywords only in the copy of the text that writes `l` as
    `i`. Nothing was decoded: both negations are plain text, so the rule stays a review."""
    spelled = "iota" if "iota" in keywords else "ignore previous instructions"
    look_alike = spelled.replace("i", "l", 1)
    assert _decision(keywords, f"do not beta. do not {look_alike}", fast) == ("allow_redacted", "review")
    assert _decision(keywords, f"never beta. never {look_alike}", fast) == ("allow_redacted", "review")
    # The same keyword standing on its own is live, as on main.
    assert _decision(keywords, f"do not beta. {spelled}", fast) == ("block", "high")
