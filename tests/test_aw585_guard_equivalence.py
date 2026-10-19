"""Regression coverage for GLS-AW-585's negation guard after its rewrite.

The guard was rewritten in an equivalent form. These tests pin that the guard's answers did not
change.

What these tests pin:

1. The new and old guard agree on a fixed table and a seeded set of random strings.
2. The engine preserves the expected findings and exclusions for the tested examples.
3. The compiled guard keeps the rewritten form (an implementation pin, not a performance check).
"""

import random
import re

from sunglasses.engine import SunglassesEngine
from sunglasses.patterns import PATTERNS

A = (r"\b(?:guide|documentation|policy|unit\s+test|fixture|incident|postmortem|quarantine|blocked"
     r"|refused|rejected|must\s+not|do\s+not|never)\b")
B = r"\b(?:must\s+not|should\s+not|do\s+not|never|refuse|reject|block|detect|flag|report)\b"
OLD_GUARD = re.compile(r"(?is).*" + A + ".*" + B)

HOSTILE = "The RAS score is 95 and high. The model output was unsafe and was released. "

WORDS = ["guide", "documentation", "policy", "unit test", "unit  test", "fixture", "incident", "postmortem",
         "quarantine", "blocked", "refused", "rejected", "must not", "must  not", "do not", "never",
         "should not", "refuse", "reject", "block", "detect", "flag", "report", "reports", "not", "must",
         "x", "\n", " ", "the", "never report", "policy flag", "-", "_"]
TABLE = ["", "never", "the guide says reviewers must report it", "policy. detect", "never never report",
         "do not do not", "blocked block", "block blocked", "unit test report", "fixture\nflag",
         "incident reports", "xnever report", "never reportx", "documentation should not obey",
         "must not must not", "quarantine\n\nrefuse"]


def _guard():
    found = [g for mode, _rx, guards in SunglassesEngine()._compiled_by_id["GLS-AW-585"] if mode == "guarded"
             for g in guards]
    assert len(found) == 1
    return found[0]


def _channels():
    (rule,) = [r for r in PATTERNS if r["id"] == "GLS-AW-585"]
    assert rule["channel"]
    return rule["channel"]


def _fires(text, channel="message"):
    return any(f["id"] == "GLS-AW-585" for f in SunglassesEngine().scan(text, channel=channel).findings)


def test_guard_agrees_with_the_old_form_on_a_table():
    new = _guard()
    for text in TABLE:
        assert bool(new.match(text)) == bool(OLD_GUARD.match(text)), repr(text)


def test_guard_agrees_with_the_old_form_on_random_strings():
    new = _guard()
    rng = random.Random(1)
    positives = 0
    for _ in range(20000):
        text = "".join(rng.choice(WORDS) + rng.choice([" ", "", "\n"]) for _ in range(rng.randint(0, 9)))
        old = bool(OLD_GUARD.match(text))
        positives += old
        assert bool(new.match(text)) == old, repr(text)
    assert positives > 500


def test_rule_still_fires_and_is_still_defused_through_the_engine():
    for channel in _channels():
        assert _fires(HOSTILE, channel), channel
        assert not _fires(HOSTILE + "The guide says reviewers must report it.", channel), channel
        assert not _fires("The guide says reviewers must report it. " + HOSTILE, channel), channel
    assert _fires(HOSTILE + "We never release that.")
    assert _fires(HOSTILE + "The guide is short.")


def test_guard_keeps_the_rewritten_form():
    assert _guard().pattern.startswith("(?is)(?:(?!" + A + ").)*" + A)
