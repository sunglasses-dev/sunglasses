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
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "report_unskippable_rules.py"

# Measured 2026-09-12 on main. This is a RATCHET, not a target: every one of
# these is a rule where splitting the alternation would give the prefilter its
# literals back. The number may fall and may not rise. Lower it when one is
# fixed, the way GLS-ENC-ALT-210 was.
BASELINE = 13


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


def test_the_population_does_not_grow():
    findings = _report()
    assert len(findings) <= BASELINE, (
        f"{len(findings)} regexes are unskippable because one branch derives "
        f"nothing, baseline {BASELINE}. A new alternation has put a literal-free "
        "branch beside branches that would otherwise be skippable, so the whole "
        "rule now runs on every document. Split the alternation into separate "
        "regex entries, or lower the baseline if you are removing one."
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

    A literal-free branch beside a derivable one is reported. The same two
    branches as separate regexes are not, because each derives on its own.
    That is exactly the repair applied to GLS-ENC-ALT-210.
    """
    sys.path.insert(0, str(ROOT))
    from sunglasses import _prefilter as pf
    blind = r"[⠀-⣿]{8,}"
    derivable = r"\bdecode\b.{0,40}\bbase64\b"

    together = f"(?is)({derivable})|({blind})"
    assert pf.requirement(together) == (), (
        "the merged form should derive nothing; if it does, the deriver changed "
        "and this report needs rewriting"
    )
    assert pf.requirement(f"(?is){derivable}"), (
        "the derivable branch must derive on its own, or the control proves nothing"
    )
