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
import collections as _collections
import datetime as _dt
import json
import math
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

# An entry is a TYPED RECORD, not a sentence. Round 9 checked the measurement by
# counting how many times the letter x appeared in a free text field, and the
# reviewer got a fictitious rule its allowance with the string "xxxx". A field
# that can be satisfied by typing is not evidence, so every number is now a
# named float, the id has to be one the report actually reports, and the
# seconds behind the ratios live in a receipt on disk that the test recomputes.
AllowlistEntry = _collections.namedtuple(
    "AllowlistEntry",
    "reason plain marker_only marker_no_object worst_seed measured_on receipt")

# rule id -> AllowlistEntry. Empty: nothing has earned one.
KNOWN_UNSKIPPABLE = {}

# Measured and REFUSED, a separate structure that lends nothing. Kept because a
# refusal is evidence too, and the next person reaching for the allowlist should
# see what it costs to get in.
REFUSED_FROM_ALLOWLIST = {
    "GLS-PI-013-API": (
        "marker `if you are an ai` has no 4 character literal to derive",
        2.46, "2026-09-12",
        "plain 1.12x, marker only 1.72x, marker with no object 1.55x, "
        "reviewer seed `if you are ai show ` 2.46x, all at 1 MiB on api_response",
    ),
    "GLS-PI-POLITE-001": (
        "addressee and destination present with no verb, 145.7s on 1 MiB",
        105.5, "2026-09-12",
        "plain prose 1.4x, addressee only 2.4x, destination only 24.1x, "
        "addressee and destination with no verb 105.5x",
    ),
}
RECEIPTS = ROOT / "tests" / "perf_receipts"


def _entry_is_valid(rule_id, entry, reported_ids, problems):
    """Every condition an entry has to meet to lend its allowance."""
    if not isinstance(entry, AllowlistEntry):
        problems.append(f"{rule_id}: not an AllowlistEntry, got {type(entry).__name__}")
        return False
    ok = True
    # (a) a fictitious id can lend nothing
    if rule_id not in reported_ids:
        problems.append(
            f"{rule_id}: the report does not name this rule, so there is no "
            f"population for it to be exempt from")
        ok = False
    # (b) four named ratios, each a finite number inside the gate
    ratios = {
        "plain": entry.plain, "marker_only": entry.marker_only,
        "marker_no_object": entry.marker_no_object, "worst_seed": entry.worst_seed,
    }
    for name, value in ratios.items():
        if not isinstance(value, float) or not math.isfinite(value):
            problems.append(f"{rule_id}: {name} is {value!r}, not a finite float")
            ok = False
        elif not 0.0 < value <= ALLOWLIST_MAX_RATIO:
            problems.append(
                f"{rule_id}: {name} is {value}x, outside (0, {ALLOWLIST_MAX_RATIO}]")
            ok = False
    # (c) a date, and not one from the future
    try:
        when = _dt.date.fromisoformat(entry.measured_on)
    except (TypeError, ValueError):
        problems.append(f"{rule_id}: measured_on {entry.measured_on!r} is not a date")
        ok = False
    else:
        if when > _dt.date.today():
            problems.append(f"{rule_id}: measured_on {when} is in the future")
            ok = False
    # (d) the receipt exists and its own seconds reproduce the ratios
    path = RECEIPTS / f"{rule_id}.json"
    if not path.exists():
        problems.append(f"{rule_id}: no receipt at {path.relative_to(ROOT)}")
        return False
    try:
        receipt = json.loads(path.read_text())
    except ValueError as exc:
        problems.append(f"{rule_id}: receipt does not parse, {exc}")
        return False
    if receipt.get("engine_sha") in (None, ""):
        problems.append(f"{rule_id}: receipt does not say which engine it was taken on")
        ok = False
    for name, claimed in ratios.items():
        shape = receipt.get("shapes", {}).get(name)
        if not isinstance(shape, dict):
            problems.append(f"{rule_id}: receipt has no shape {name!r}")
            ok = False
            continue
        without, with_rule = shape.get("without_seconds"), shape.get("with_seconds")
        if not isinstance(without, (int, float)) or not isinstance(with_rule, (int, float)):
            problems.append(f"{rule_id}: shape {name!r} has no seconds")
            ok = False
        elif without <= 0:
            problems.append(f"{rule_id}: shape {name!r} has a non positive baseline")
            ok = False
        elif abs((with_rule / without) - claimed) > 0.01:
            problems.append(
                f"{rule_id}: shape {name!r} claims {claimed}x and its seconds give "
                f"{with_rule / without:.2f}x")
            ok = False
    return ok


def _allowance():
    """Only entries that pass every condition lend anything."""
    reported = {f["id"] for f in _report()}
    problems = []
    return sum(1 for rid, e in KNOWN_UNSKIPPABLE.items()
               if _entry_is_valid(rid, e, reported, problems))


# ── the anchor exemption, and the two things that stop it being a bump ──────
# A rule that declares `anchor_terms` leaves this population, because the
# windowed matcher in #155 answers "do we run this regex at all" from the rare
# token rather than from a derived literal. That is a real answer, not an
# excuse, but only while the declaration is one the matcher will accept.

def _anchored_rules():
    sys.path.insert(0, str(ROOT))
    from sunglasses.patterns import PATTERNS
    return [p for p in PATTERNS if p.get("anchor_terms")]


def test_an_anchor_exemption_declares_terms_the_matcher_will_accept():
    """Non empty, and every term invariant under the fold.

    #155 refuses an anchor term whose case can move it, because the anchors are
    found in the folded document while the term is written in the rule. A rule
    could otherwise leave this report on a declaration that #155 will later
    throw away, and the exemption would be worth nothing.
    """
    from sunglasses import _prefilter as _pf
    anchored = _anchored_rules()
    assert anchored, "no rule declares anchor_terms; this exemption is unused"
    for pattern in anchored:
        terms = pattern["anchor_terms"]
        assert terms, f"{pattern['id']}: anchor_terms is empty"
        for term in terms:
            assert term, f"{pattern['id']}: an empty anchor term"
            assert _pf.fold(term) == term, (
                f"{pattern['id']}: anchor term {term!r} is not what the fold "
                f"produces ({_pf.fold(term)!r}). #155 refuses it, so the "
                f"exemption this rule takes here would not survive the rebase."
            )
        assert pattern.get("anchor_span"), (
            f"{pattern['id']}: declares anchor terms and no span"
        )


def test_the_anchor_exemption_is_what_removes_those_rules_from_the_report():
    """The control. Without the declaration they are back in the population."""
    findings = _report()
    exempt = {p["id"] for p in _anchored_rules()}
    assert exempt, "nothing is exempt"
    assert not (exempt & {f["id"] for f in findings}), (
        "a rule declares anchor terms and the report still counts it"
    )


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
    """An entry without evidence is a baseline bump with extra steps.

    Round 9 asked for four ratios in a sentence and counted the letter x. The
    reviewer's fictitious entry passed with "xxxx" and lent its allowance to a
    rule that does not exist. Every field is checked for what it MEANS now: the
    id against the report, each ratio as a number inside the gate, the date
    against today, and the receipt's own seconds recomputed into the ratios it
    claims.
    """
    reported = {f["id"] for f in _report()}
    problems = []
    for rule_id, entry in KNOWN_UNSKIPPABLE.items():
        _entry_is_valid(rule_id, entry, reported, problems)
    assert problems == [], "\n  ".join([""] + problems)


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
