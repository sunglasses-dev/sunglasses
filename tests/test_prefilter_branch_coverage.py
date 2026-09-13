"""The shape that produced three different-looking defects in one week.

`_prefilter` takes ONE clause from every branch of an alternation and unions
them, because a match could arrive through any branch. So a single branch that
derives nothing drops the required-literal set for the WHOLE regex, and every
other branch in it stops being skippable no matter how selective it is.

Found three times by chasing three unrelated symptoms:

  a 255 second scan of a 27 KB document   GLS-ENC-ALT-210, a bare braille
                                          character class beside a base64 branch
  detections missed on folded text        the #152 siblings, `api key` and
                                          `env var` start with 3-character runs
  a cost gate that would not come down    the #149 destination class, an email
                                          local part starts with a character class

`scripts/report_unskippable_rules.py` finds the shape directly instead of
waiting for the next symptom. This file keeps the report honest and keeps the
population from growing quietly.
"""
import json
import re
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "report_unskippable_rules.py"

# Measured 2026-09-12. This is a RATCHET, not a target: every one of these is a
# rule where splitting the alternation would give the prefilter its literals
# back. The number may fall and may not rise. Lower it when one is fixed, the
# way GLS-ENC-ALT-210 was.
#
# 13 on main. 12 here, because the class clause work on this branch gives
# GLS-ENC-ALT-210 a requirement it did not have. A ratchet left loose for a
# round is a ratchet that is not doing its job, so it moves with the change
# rather than after it.
BASELINE = 12


def _report():
    proc = subprocess.run([sys.executable, str(SCRIPT), "--json"],
                          cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_the_report_runs_and_is_machine_readable():
    findings = _report()
    assert isinstance(findings, list)
    for f in findings:
        assert {"id", "regex_index", "branches", "would_derive_alone"} <= set(f)


# ── the allowlist, and why an entry costs a measurement ─────────────────────
# A bare number can only be raised, and raising it is indistinguishable from
# giving up. Some rules genuinely cannot derive a literal: GLS-PI-013-API's
# marker is `if you are an ai`, and every word in it is shorter than
# MIN_LITERAL or on the denylist. The rule is not wrong; the deriver simply has
# nothing to hold.
#
# So a rule may be allowed PROVIDED it is measured, and the measurement is the
# price. Four shapes at 1 MiB, each timed against the same engine WITHOUT that
# rule in the same process: plain prose, the marker alone, the marker with no
# object, and the reviewer's worst repetition seed. The worst of the four must
# be at most ALLOWLIST_MAX_RATIO. That is what separates a rule the prefilter
# cannot help from a rule that is a denial of service: GLS-PI-POLITE-001
# measures 105x on one of these shapes, and no amount of allowlisting should
# hide that.
ALLOWLIST_MAX_RATIO = 2.0

# rule id -> (reason, worst measured ratio, the date it was measured)
KNOWN_UNSKIPPABLE = {}

# Measured and REFUSED. Kept because a refusal is evidence too, and because the
# next person to reach for the allowlist should see what it costs to get in.
REFUSED_FROM_ALLOWLIST = {
    "GLS-PI-013-API": (
        "marker `if you are an ai` has no 4 character literal to derive",
        2.46, "2026-09-12",
        "plain prose 1.12x, marker only 1.72x, marker with no object 1.55x, "
        "reviewer seed `if you are ai show ` 2.46x, all at 1 MiB on api_response",
    ),
    "GLS-PI-POLITE-001": (
        "addressee and destination present with no verb, 145.7s on 1 MiB",
        105.5, "2026-09-12",
        "plain prose 1.4x, addressee only 2.4x, destination only 24.1x, "
        "addressee and destination with no verb 105.5x",
    ),
}


def _allowance():
    return len(KNOWN_UNSKIPPABLE)


def test_the_population_does_not_grow():
    findings = _report()
    allowed = BASELINE + _allowance()
    assert len(findings) <= allowed, (
        f"{len(findings)} regexes are unskippable because one branch derives "
        f"nothing, baseline {BASELINE} plus {_allowance()} allowlisted. A new "
        "alternation has put a literal-free branch beside branches that would "
        "otherwise be skippable, so the whole rule now runs on every document. "
        "Split the alternation into separate regex entries, lower the baseline "
        "if you are removing one, or add an allowlist entry WITH the four shape "
        "measurement its docstring describes."
    )


def test_every_allowlist_entry_carries_its_measurement():
    """An entry without evidence is a baseline bump with extra steps."""
    for rule_id, entry in KNOWN_UNSKIPPABLE.items():
        assert isinstance(entry, tuple) and len(entry) == 4, (
            f"{rule_id}: an allowlist entry is (reason, worst ratio, date, "
            f"the four shape numbers), got {entry!r}"
        )
        reason, ratio, measured_on, shapes = entry
        assert isinstance(reason, str) and len(reason) > 20, (
            f"{rule_id}: say WHY the deriver has nothing to hold, in a sentence"
        )
        assert isinstance(ratio, float), f"{rule_id}: the worst ratio is a number"
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", measured_on), (
            f"{rule_id}: when was this measured"
        )
        assert isinstance(shapes, str) and shapes.count("x") >= 4, (
            f"{rule_id}: all four shapes and their ratios, or the entry is a "
            f"claim rather than a measurement"
        )
        assert ratio <= ALLOWLIST_MAX_RATIO, (
            f"{rule_id}: worst measured {ratio}x is over {ALLOWLIST_MAX_RATIO}x. "
            f"A rule this expensive is not one the prefilter cannot help, it is "
            f"one that needs fixing. {shapes}"
        )


def test_the_refused_entries_would_actually_be_refused():
    """The control on the control.

    Both refusals are here because they were measured, not because they were
    guessed. If either would now pass the gate, the gate has been loosened and
    the entry should move rather than sit here as decoration.
    """
    assert REFUSED_FROM_ALLOWLIST, "nothing was refused; this test proves nothing"
    for rule_id, (_reason, ratio, _on, _shapes) in REFUSED_FROM_ALLOWLIST.items():
        assert ratio > ALLOWLIST_MAX_RATIO, (
            f"{rule_id} was refused at {ratio}x but the gate is now "
            f"{ALLOWLIST_MAX_RATIO}x, so it would be admitted. Move it or "
            f"restore the gate."
        )
        assert rule_id not in KNOWN_UNSKIPPABLE, (
            f"{rule_id} is both allowed and refused"
        )


def test_every_finding_really_has_an_empty_requirement():
    """The report must not cry wolf: verify each hit against the real deriver."""
    sys.path.insert(0, str(ROOT))
    from sunglasses import _prefilter as pf
    from sunglasses.patterns import PATTERNS
    by_id = {p["id"]: p for p in PATTERNS}
    for f in _report():
        source = by_id[f["id"]]["regex"][f["regex_index"]]
        assert pf.requirement(source) == (), (
            f"{f['id']} regex[{f['regex_index']}] was reported as underivable "
            "but the deriver returns a requirement for it"
        )


def test_a_split_alternation_is_not_reported():
    """The control: the shape the report exists to find, and its repair.

    A branch that derives NOTHING, beside a derivable one, blinds the whole
    regex and is reported. The same two branches as separate regexes are not,
    because each derives on its own. That is the repair the report exists to
    suggest.

    The braille class used to be the example here. It is not one any more: the
    class clause work gives a bare positive class its own requirement, so
    `decode OR braille` now derives and the merged form is no longer blind. A
    negated class still derives nothing, and there is no plan for it to, since
    it matches nearly everything. That is the shape the remaining twelve have.
    """
    sys.path.insert(0, str(ROOT))
    from sunglasses import _prefilter as pf
    blind = r"[^.\n]{8,}"
    derivable = r"\bdecode\b.{0,40}\bbase64\b"

    together = f"(?is)({derivable})|({blind})"
    assert pf.requirement(together) == (), (
        "the merged form should derive nothing; if it does, the deriver changed "
        "and this report needs rewriting"
    )
    assert pf.requirement(f"(?is){derivable}"), (
        "the derivable branch must derive on its own, or the control proves nothing"
    )
    # And the branch that USED to be blind is not any more, which is why the
    # ratchet moved by one.
    assert pf.requirement(r"(?is)(\bdecode\b.{0,40}\bbase64\b)|([⠀-⣿]{8,})"), (
        "a positive class beside a literal branch should now derive a clause"
    )
