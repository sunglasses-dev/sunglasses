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
import importlib.util
import json
import math
import re
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "report_unskippable_rules.py"

# ── the ratchet is a SET, not a count ───────────────────────────────────────
# Round 10 counted. The reviewer removed GLS-PI-013-API's anchor declaration,
# which put its two regexes back into the report (12 -> 14), then wrote two
# invented 1.0/1.0 receipts for GLS-TP-002 and GLS-SC-014, both already in the
# baseline, and every check passed. Nothing was measured. A member had lent its
# allowance to a different rule, because an allowance that is a NUMBER is
# fungible and no amount of extra field checking changes that.
#
# So the baseline is the frozen LIST of what is unskippable, and an allowlist
# entry excuses only the id it names. A returned PI-013-API now needs a
# PI-013-API entry with a PI-013-API receipt, and a receipt for TP-002 cannot
# help it. The count survives only as something to print.
#
# Measured 2026-09-12 on this branch. This is a RATCHET, not a target: every
# one of these is a rule where splitting the alternation would give the
# prefilter its literals back. Entries may leave and may not arrive. GLS-ENC-
# ALT-210 left it, which is what leaving looks like.
#
# 13 on main. 12 here, because the class clause work on this branch gives
# GLS-ENC-ALT-210 a requirement it did not have.
BASELINE_PAIRS = frozenset({
    ("GLS-AB-001", 1),
    ("GLS-AW-078", 1),
    ("GLS-AW-093", 0),
    ("GLS-AW-144", 0),
    ("GLS-CI-005", 0),
    ("GLS-CI-007", 0),
    ("GLS-EX-009", 0),
    ("GLS-GHSA-PI-202", 0),
    ("GLS-I18N-LR-203", 0),
    ("GLS-PE-004", 0),
    ("GLS-SC-014", 0),
    ("GLS-TP-002", 0),
})
BASELINE = len(BASELINE_PAIRS)          # printed, never asserted against alone


def _report():
    proc = subprocess.run([sys.executable, str(SCRIPT), "--json"],
                          cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _reported_pairs():
    return {(f["id"], f["regex_index"]) for f in _report()}


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
# reviewer got a fictitious rule its allowance with the string "xxxx". Round 10
# typed every field and the reviewer got the allowance anyway, with two receipts
# it wrote by hand for rules that were already in the baseline. So the fields
# are typed AND the receipt is bound to the thing it measured: to its own rule
# id, to its own physical file, and to the exact engine bytes it was taken on.
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

# The production bytes a measurement is only valid for. Change any of them and
# every receipt is stale, because the number it records was taken on a different
# engine. The reviewer accepted a receipt naming main's sha, and one naming
# "xxxx", and one naming an empty list; none of those is the tree under test.
_ENGINE_FILES = ("engine.py", "_prefilter.py", "patterns.py")


def _engine_sha(root=None):
    """sha256 over the production files a timing number depends on."""
    import hashlib
    root = pathlib.Path(root or ROOT)
    digest = hashlib.sha256()
    for name in _ENGINE_FILES:
        digest.update(name.encode())
        digest.update((root / "sunglasses" / name).read_bytes())
    return digest.hexdigest()


def _entry_is_valid(rule_id, entry, reported_ids, problems, receipts=None):
    """Every condition an entry has to meet to lend its allowance to ITS OWN id."""
    receipts = pathlib.Path(receipts or RECEIPTS)
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
    numeric = set()
    for name, value in ratios.items():
        if isinstance(value, bool) or not isinstance(value, float) \
                or not math.isfinite(value):
            problems.append(f"{rule_id}: {name} is {value!r}, not a finite float")
            ok = False
        elif not 0.0 < value <= ALLOWLIST_MAX_RATIO:
            problems.append(
                f"{rule_id}: {name} is {value}x, outside (0, {ALLOWLIST_MAX_RATIO}]")
            ok = False
        else:
            numeric.add(name)
    # (c) a reason someone wrote, and a date, and not one from the future
    if not isinstance(entry.reason, str) or not entry.reason.strip():
        problems.append(f"{rule_id}: reason is {entry.reason!r}; say why")
        ok = False
    entry_date = None
    try:
        entry_date = _dt.date.fromisoformat(entry.measured_on)
    except (TypeError, ValueError):
        problems.append(f"{rule_id}: measured_on {entry.measured_on!r} is not a date")
        ok = False
    else:
        if entry_date > _dt.date.today():
            problems.append(f"{rule_id}: measured_on {entry_date} is in the future")
            ok = False
    # (d) the receipt is this rule's own file, and nothing else's
    path = receipts / f"{rule_id}.json"
    if not path.exists():
        problems.append(f"{rule_id}: no receipt at {path.name}")
        return False
    if path.is_symlink():
        problems.append(
            f"{rule_id}: {path.name} is a symlink. Two entries sharing one "
            f"physical receipt is one measurement counted twice.")
        return False
    try:
        receipt = json.loads(path.read_text())
    except ValueError as exc:
        problems.append(f"{rule_id}: receipt does not parse, {exc}")
        return False
    # (d1) the receipt says which rule it measured, and it is this one
    if receipt.get("rule_id") != rule_id:
        problems.append(
            f"{rule_id}: receipt body says rule_id {receipt.get('rule_id')!r}. A "
            f"measurement of another rule cannot excuse this one.")
        ok = False
    # (d2) and which engine, and it is the tree under test
    if receipt.get("engine_sha") != _engine_sha():
        problems.append(
            f"{rule_id}: receipt engine_sha {receipt.get('engine_sha')!r} is not "
            f"this tree's {_engine_sha()[:12]}...; the number was taken on "
            f"different production bytes, so re-measure")
        ok = False
    # (d3) the receipt's own date, consistent with the entry's
    try:
        taken = _dt.date.fromisoformat(receipt.get("measured_on", ""))
    except (TypeError, ValueError):
        problems.append(f"{rule_id}: receipt measured_on "
                        f"{receipt.get('measured_on')!r} is not a date")
        ok = False
    else:
        if taken > _dt.date.today():
            problems.append(f"{rule_id}: receipt was taken on {taken}, in the future")
            ok = False
        if entry_date is not None and taken < entry_date - _dt.timedelta(days=1):
            problems.append(
                f"{rule_id}: receipt taken {taken}, entry claims {entry_date}; the "
                f"entry is not describing this measurement")
            ok = False
    # (d4) the raw seconds are seconds, and they reproduce the claimed ratios
    for name, claimed in ratios.items():
        shape = receipt.get("shapes", {}).get(name)
        if not isinstance(shape, dict):
            problems.append(f"{rule_id}: receipt has no shape {name!r}")
            ok = False
            continue
        without, with_rule = shape.get("without_seconds"), shape.get("with_seconds")
        bad = [f"{k}={v!r}" for k, v in
               (("without_seconds", without), ("with_seconds", with_rule))
               if isinstance(v, bool) or not isinstance(v, (int, float))
               or not math.isfinite(v) or v <= 0]
        if bad:
            problems.append(
                f"{rule_id}: shape {name!r} {', '.join(bad)}; seconds must be "
                f"finite positive numbers")
            ok = False
        elif name not in numeric:
            # The claimed value already failed its own type check above; there
            # is nothing to reproduce it against, and arithmetic on it would
            # raise rather than report. A validator that can be crashed by its
            # input is a validator that can be got past.
            continue
        elif abs((with_rule / without) - claimed) > 0.01:
            problems.append(
                f"{rule_id}: shape {name!r} claims {claimed}x and its seconds give "
                f"{with_rule / without:.2f}x")
            ok = False
    return ok


def _excused_ids(problems=None):
    """The ids a VALID entry excuses. An entry excuses only the id it names."""
    reported = {f["id"] for f in _report()}
    problems = [] if problems is None else problems
    return {rid for rid, e in KNOWN_UNSKIPPABLE.items()
            if _entry_is_valid(rid, e, reported, problems)}


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
    """Set containment, not a count.

    A pair may leave this population. Nothing may arrive in it without either
    the baseline changing deliberately or that exact rule earning a measured
    allowlist entry of its own.
    """
    found = _reported_pairs()
    excused = _excused_ids()
    arrived = sorted(p for p in found - BASELINE_PAIRS if p[0] not in excused)
    print(f"  unskippable regexes: {len(found)} "
          f"(baseline {BASELINE}, excused ids {sorted(excused) or 'none'})")
    assert arrived == [], (
        f"{arrived} became unskippable and nothing accounts for them. A new "
        f"alternation has put a literal-free branch beside branches that would "
        f"otherwise be skippable, so the whole rule now runs on every document. "
        f"Split the alternation into separate regex entries, remove the pair "
        f"from BASELINE_PAIRS if you are fixing one, or add an allowlist entry "
        f"FOR THAT RULE with the four shape measurement its docstring "
        f"describes. An entry for another rule does not help: that was the "
        f"round 10 defect."
    )


def test_a_pair_that_left_the_baseline_is_removed_from_it():
    """The other direction. A baseline that still lists a rule nobody reports
    is a ratchet with slack in it, and slack is where the next growth hides."""
    stale = sorted(BASELINE_PAIRS - _reported_pairs())
    assert stale == [], (
        f"{stale} are in BASELINE_PAIRS and are no longer unskippable. Delete "
        f"them; the ratchet only means something while it is tight.")


def test_every_allowlist_entry_carries_its_measurement():
    """An entry without evidence is a baseline bump with extra steps."""
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


# ── the reviewer's own attacks, committed ───────────────────────────────────
# Each of these passed round 10. They are here as tests rather than as a
# paragraph saying they were tried, because the next person to relax one of
# these conditions should have to delete an assertion to do it.

def _receipt(rule_id, **over):
    """A receipt that is valid in every way the caller does not override."""
    body = {
        "rule_id": rule_id,
        "engine_sha": _engine_sha(),
        "measured_on": _dt.date.today().isoformat(),
        "shapes": {name: {"without_seconds": 1.0, "with_seconds": 1.0}
                   for name in ("plain", "marker_only", "marker_no_object",
                                "worst_seed")},
    }
    body.update(over)
    return body


def _entry(**over):
    fields = dict(reason="measured", plain=1.0, marker_only=1.0,
                  marker_no_object=1.0, worst_seed=1.0,
                  measured_on=_dt.date.today().isoformat(),
                  receipt="tests/perf_receipts")
    fields.update(over)
    return AllowlistEntry(**fields)


def _judge(tmp_path, rule_id, entry, receipt_body, reported=None, name=None):
    """Run one entry through the real validator with a receipts dir we control."""
    (tmp_path / f"{name or rule_id}.json").write_text(json.dumps(receipt_body))
    problems = []
    ok = _entry_is_valid(rule_id, entry,
                         {rule_id} if reported is None else reported, problems,
                         receipts=tmp_path)
    return ok, problems


# ── the controls below run the real functions, not copies of them ───────────
# Round 12 wrote this next control by copying the population comprehension into
# the test body with a hand-written `excused` set. It never called
# `_excused_ids`, so `return {"GLS-PI-013-API"}` at the top of that function
# passed all 36 root checks with an empty allowlist, no receipts and the real
# 14-pair population. A control that reimplements the thing it is controlling
# proves the reimplementation.
#
# The obstacle was `_report()`: it shells out, which is right for the gate and
# wrong for a control that has to ask what happens when a rule LOSES its
# declaration, because a subprocess reads the files on disk. So the control
# loads `scan()`, the function `--json` prints, and varies the PATTERNS list
# that function reads. `test_the_in_process_report_is_the_same_report` holds the
# harness to the subprocess on the untouched tree; if they ever disagree, these
# controls are measuring a copy and that test says so.

def _report_module():
    """The report script as a module, so its PATTERNS can be varied."""
    spec = importlib.util.spec_from_file_location("_p1b_report_script", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _report_without_anchor_declaration(rule_id):
    """What the report says when `rule_id` declares no anchor terms.

    Idempotent on purpose. The postcondition that matters is that the rule is
    IN the returned report, and the caller asserts it; requiring a declaration
    to remove here would make this raise, rather than test the seam, on a tree
    where the declaration has already been taken away.
    """
    module = _report_module()
    varied = [{k: v for k, v in p.items() if k != "anchor_terms"}
              if p["id"] == rule_id else p
              for p in module.PATTERNS]
    assert len(varied) == len(module.PATTERNS)
    assert any(p["id"] == rule_id for p in varied), f"{rule_id} is not a rule"
    module.PATTERNS = varied
    return module.scan()


def _allowlist(monkeypatch, entries, receipts):
    """Point the REAL `_excused_ids` at an allowlist and a receipts directory."""
    module = sys.modules[__name__]
    monkeypatch.setattr(module, "KNOWN_UNSKIPPABLE", entries)
    monkeypatch.setattr(module, "RECEIPTS", receipts)


def test_the_in_process_report_is_the_same_report():
    """The harness the controls use is the gate's own report, not a copy."""
    assert _report_module().scan() == _report()


def test_control_an_empty_allowlist_excuses_nothing(monkeypatch, tmp_path):
    """`_excused_ids` answers from the allowlist. Round 12 never asked it.

    This is the assertion ASTRA's `return {"GLS-PI-013-API"}` has to get past.
    """
    _allowlist(monkeypatch, {}, tmp_path)
    assert _excused_ids() == set()


def test_control_a_valid_entry_excuses_exactly_the_id_it_names(monkeypatch, tmp_path):
    (tmp_path / "GLS-TP-002.json").write_text(json.dumps(_receipt("GLS-TP-002")))
    _allowlist(monkeypatch, {"GLS-TP-002": _entry()}, tmp_path)
    problems = []
    assert _excused_ids(problems) == {"GLS-TP-002"}, problems
    assert problems == []


def test_control_an_invalid_entry_excuses_nothing(monkeypatch, tmp_path):
    (tmp_path / "GLS-TP-002.json").write_text(
        json.dumps(_receipt("GLS-TP-002", engine_sha="0" * 64)))
    _allowlist(monkeypatch, {"GLS-TP-002": _entry()}, tmp_path)
    problems = []
    assert _excused_ids(problems) == set()
    assert any("engine_sha" in p for p in problems), problems


def test_control_a_member_cannot_lend_its_allowance_to_another_rule(monkeypatch, tmp_path):
    """THE round 10 defect, executed through the real path.

    The reviewer removed GLS-PI-013-API's anchor declaration, which returned its
    two regexes to the report, then wrote perfectly consistent receipts for
    GLS-TP-002 and GLS-SC-014. Both are real baseline members, so every field
    checked out and the count rose by two. Under set containment the returned
    pairs are simply not excused by anyone else's entry.

    Every step here is the shipped one: the real report with one declaration
    removed, the real `_excused_ids`, and the real population test function.
    The two entries are asserted VALID before the population is asked, because
    a control where the entries silently fail to validate would pass for the
    wrong reason.
    """
    returned = _report_without_anchor_declaration("GLS-PI-013-API")
    monkeypatch.setattr(sys.modules[__name__], "_report", lambda: returned)
    assert ("GLS-PI-013-API", 0) in _reported_pairs(), (
        "removing the declaration did not return GLS-PI-013-API to the report, "
        "so nothing below is under test")

    _allowlist(monkeypatch, {}, tmp_path)
    with pytest.raises(AssertionError) as unexcused:
        test_the_population_does_not_grow()
    assert "GLS-PI-013-API" in str(unexcused.value), unexcused.value

    for rule_id in ("GLS-TP-002", "GLS-SC-014"):
        (tmp_path / f"{rule_id}.json").write_text(json.dumps(_receipt(rule_id)))
    _allowlist(monkeypatch,
               {rid: _entry() for rid in ("GLS-TP-002", "GLS-SC-014")}, tmp_path)
    problems = []
    assert _excused_ids(problems) == {"GLS-TP-002", "GLS-SC-014"}, problems
    with pytest.raises(AssertionError) as lent:
        test_the_population_does_not_grow()
    assert "GLS-PI-013-API" in str(lent.value), (
        "a measurement of TP-002 and SC-014 excused PI-013-API; the allowance "
        "is fungible again")


def test_control_a_receipt_for_another_rule_is_rejected(tmp_path):
    ok, problems = _judge(tmp_path, "GLS-TP-002", _entry(),
                          _receipt("GLS-SC-014"))
    assert not ok and any("receipt body says rule_id" in p for p in problems), problems


def test_control_a_receipt_taken_on_a_different_engine_is_rejected(tmp_path):
    for sha in ("xxxx", [], "", None, "0" * 64):
        ok, problems = _judge(tmp_path, "GLS-TP-002", _entry(),
                              _receipt("GLS-TP-002", engine_sha=sha))
        assert not ok and any("engine_sha" in p for p in problems), (sha, problems)


def test_control_a_symlinked_receipt_cannot_be_counted_twice(tmp_path):
    real = tmp_path / "GLS-TP-002.json"
    real.write_text(json.dumps(_receipt("GLS-TP-002")))
    link = tmp_path / "GLS-SC-014.json"
    link.symlink_to(real)
    problems = []
    ok = _entry_is_valid("GLS-SC-014", _entry(), {"GLS-SC-014"}, problems,
                         receipts=tmp_path)
    assert not ok and any("symlink" in p for p in problems), problems


@pytest.mark.parametrize("seconds", [
    float("nan"), float("inf"), -1.0, 0.0, True, "1.0", None])
def test_control_seconds_that_are_not_seconds_are_rejected(tmp_path, seconds):
    body = _receipt("GLS-TP-002")
    body["shapes"]["plain"]["with_seconds"] = seconds
    ok, problems = _judge(tmp_path, "GLS-TP-002", _entry(), body)
    assert not ok and any("seconds must be" in p or "claims" in p
                          for p in problems), (seconds, problems)


@pytest.mark.parametrize("ratio", [float("nan"), float("inf"), 0.0, -1.0, True,
                                   2.0001, "1.0"])
def test_control_a_ratio_that_is_not_a_ratio_is_rejected(tmp_path, ratio):
    ok, problems = _judge(tmp_path, "GLS-TP-002", _entry(plain=ratio),
                          _receipt("GLS-TP-002"))
    assert not ok, (ratio, problems)


def test_control_exactly_the_gate_is_still_accepted(tmp_path):
    """2.0 is inside the gate as written. A control that moved the gate while
    tightening the mechanics would be a quiet policy change."""
    body = _receipt("GLS-TP-002")
    for shape in body["shapes"].values():
        shape.update(without_seconds=1.0, with_seconds=2.0)
    ok, problems = _judge(tmp_path, "GLS-TP-002",
                          _entry(plain=2.0, marker_only=2.0,
                                 marker_no_object=2.0, worst_seed=2.0), body)
    assert ok, problems


def test_control_an_empty_reason_is_rejected(tmp_path):
    for reason in ("", "   ", None):
        ok, problems = _judge(tmp_path, "GLS-TP-002", _entry(reason=reason),
                              _receipt("GLS-TP-002"))
        assert not ok and any("reason" in p for p in problems), (reason, problems)


def test_control_a_receipt_older_than_its_entry_is_rejected(tmp_path):
    old = (_dt.date.today() - _dt.timedelta(days=5)).isoformat()
    ok, problems = _judge(tmp_path, "GLS-TP-002", _entry(),
                          _receipt("GLS-TP-002", measured_on=old))
    assert not ok and any("not describing this measurement" in p
                          for p in problems), problems
    # One day of slack is deliberate: a measurement taken just before midnight
    # and recorded just after is the same measurement.
    yesterday = (_dt.date.today() - _dt.timedelta(days=1)).isoformat()
    ok, problems = _judge(tmp_path, "GLS-TP-002", _entry(),
                          _receipt("GLS-TP-002", measured_on=yesterday))
    assert ok, problems


def test_control_a_receipt_from_the_future_is_rejected(tmp_path):
    ahead = (_dt.date.today() + _dt.timedelta(days=1)).isoformat()
    ok, problems = _judge(tmp_path, "GLS-TP-002", _entry(),
                          _receipt("GLS-TP-002", measured_on=ahead))
    assert not ok and any("in the future" in p for p in problems), problems


def test_control_an_id_the_report_does_not_name_is_rejected(tmp_path):
    ok, problems = _judge(tmp_path, "GLS-DOES-NOT-EXIST", _entry(),
                          _receipt("GLS-DOES-NOT-EXIST"), reported=set())
    assert not ok and any("does not name this rule" in p for p in problems), problems


def test_control_a_valid_entry_is_still_accepted(tmp_path):
    """The whole file is refusals, so one acceptance, or the mechanics could be
    `return False` and every control above would still pass."""
    ok, problems = _judge(tmp_path, "GLS-TP-002", _entry(), _receipt("GLS-TP-002"))
    assert ok, problems


def test_the_engine_sha_covers_every_file_a_measurement_depends_on(tmp_path):
    """And changing any one of them invalidates the receipts, by construction."""
    import shutil
    copy = tmp_path / "tree"
    (copy / "sunglasses").mkdir(parents=True)
    for name in _ENGINE_FILES:
        shutil.copy(ROOT / "sunglasses" / name, copy / "sunglasses" / name)
    assert _engine_sha(copy) == _engine_sha(), "the same bytes gave a different sha"
    for name in _ENGINE_FILES:
        path = copy / "sunglasses" / name
        original = path.read_bytes()
        path.write_bytes(original + b"\n# touched\n")
        assert _engine_sha(copy) != _engine_sha(), (
            f"editing {name} did not change the sha, so a receipt taken before "
            f"that edit would still be accepted")
        path.write_bytes(original)


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
