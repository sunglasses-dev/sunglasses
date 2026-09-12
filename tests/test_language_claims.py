"""
test_language_claims.py — THE LANGUAGE NUMBER MUST COME FROM THE PATTERNS.

The README claimed "23 languages" in four places. That counted every language
NAMED anywhere in the ruleset as though it were covered, and a reader takes
"23 languages" to mean the scanner works in 23 languages. Thirteen languages
have exactly two dedicated patterns each.

It was corrected once before, in v0.5.6, and came back in PR #128. That is the
real defect: the number had no generator, so a correction was an edit that
nothing afterwards remembered. tools/gen_language_stats.py is the source now,
and these tests fail when a document disagrees with it.
"""
import json
import pathlib
import re

from tools.gen_language_stats import measure

ROOT = pathlib.Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
STATS = ROOT / "stats" / "current.json"

# The one sentence that is ALLOWED to say 23, because it is the correction
# itself. Deleting the history would be its own kind of dishonesty.
HISTORICAL = 'This section used to say "23 languages"'


def test_the_measurement_is_reproducible():
    m = measure()
    assert m["dedicated_pattern_languages"] == 13
    assert set(m["dedicated_patterns_per_language"]) == {
        "Arabic", "Chinese", "French", "German", "Hindi", "Indonesian", "Japanese",
        "Korean", "Portuguese", "Russian", "Spanish", "Turkish", "Vietnamese",
    }
    assert set(m["dedicated_patterns_per_language"].values()) == {2}, \
        "the claim is 'exactly two patterns each'; if that changed, the prose must change too"


def _stats_check(stats):
    """The stats half of the gate, against an arbitrary dict."""
    problems = []
    if "languages" in stats:
        problems.append(
            "the bare `languages` key is retired: it was one number doing two jobs, "
            "how many languages have patterns and how many are named anywhere"
        )
    measured = measure()["dedicated_pattern_languages"]
    if stats.get("dedicated_pattern_languages") != measured:
        problems.append(
            f"stats says {stats.get('dedicated_pattern_languages')!r}, patterns say {measured}"
        )
    if stats.get("language_stats_generated_by") != "tools/gen_language_stats.py":
        problems.append("the number does not name its generator")
    return problems


def test_stats_carries_the_typed_field_and_not_the_ambiguous_one():
    assert _stats_check(json.loads(STATS.read_text())) == []


def test_readme_states_the_measured_number_and_only_the_history_says_23():
    text = README.read_text()
    n = measure()["dedicated_pattern_languages"]
    for line_no, line in enumerate(text.splitlines(), 1):
        if "23 language" in line or re.search(r"\bin 23\b", line):
            assert HISTORICAL in line, (
                f"README line {line_no} still claims 23 languages as coverage: {line.strip()[:110]}"
            )
    assert re.search(rf"dedicated non-English patterns in {n} languages", text), \
        "the feature bullet must state the measured dedicated-language count"
    assert re.search(rf"{n} languages have exactly two dedicated patterns each", text), \
        "the honest-limits bullet must state the measured dedicated-language count"


def test_readme_measured_table_lists_exactly_the_measured_languages():
    text = README.read_text()
    row = [l for l in text.splitlines() if l.startswith("| **Dedicated patterns**")]
    assert len(row) == 1, "the measured coverage table must have exactly one dedicated-patterns row"
    listed = {w for w in re.findall(r"[A-Z][a-z]+", row[0])
              if w not in {"Dedicated", "Ignore"}}
    measured = set(measure()["dedicated_patterns_per_language"])
    assert measured <= listed, f"table is missing measured languages: {sorted(measured - listed)}"


# ── negative controls: each of these is how the claim came back before ────────

def _readme_check(text):
    """The README half of the gate, against arbitrary text."""
    problems = []
    n = measure()["dedicated_pattern_languages"]
    for line in text.splitlines():
        if ("23 language" in line or re.search(r"\bin 23\b", line)) and HISTORICAL not in line:
            problems.append(f"claims 23 as coverage: {line.strip()[:80]}")
    if not re.search(rf"dedicated non-English patterns in {n} languages", text):
        problems.append("feature bullet lost the measured count")
    return problems


def test_control_the_feature_bullet_reverts_to_23():
    text = README.read_text().replace(
        "dedicated non-English patterns in 13 languages",
        "dedicated non-English patterns in 23 languages")
    assert _readme_check(text), "reintroducing the 23-language coverage claim must fail the gate"


def test_control_a_new_document_line_claims_23():
    text = README.read_text() + "\nSUNGLASSES ships patterns in 23 languages.\n"
    assert _readme_check(text), "a newly added 23-language claim must fail the gate"


def test_control_the_historical_sentence_alone_is_not_a_failure():
    text = "\n".join([
        "dedicated non-English patterns in 13 languages",
        '**SUNGLASSES is English-first.** This section used to say "23 languages", which counted every',
    ])
    assert _readme_check(text) == [], "the correction's own history must remain sayable"


def test_control_stats_reverts_to_the_ambiguous_key():
    stats = json.loads(STATS.read_text())
    stats["languages"] = 23
    assert _stats_check(stats), "restoring the ambiguous `languages` key must fail the gate"


def test_control_stats_number_drifts_from_the_patterns():
    stats = json.loads(STATS.read_text())
    stats["dedicated_pattern_languages"] = 23
    assert _stats_check(stats), "a stats number that disagrees with the patterns must fail the gate"


def test_control_stats_number_loses_its_generator():
    stats = json.loads(STATS.read_text())
    del stats["language_stats_generated_by"]
    assert _stats_check(stats), "a number with no named generator is how this claim came back"
