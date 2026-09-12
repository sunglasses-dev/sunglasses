#!/usr/bin/env python3
"""Report rules the prefilter cannot skip because ONE branch spoils the set.

Why this exists
---------------
`_prefilter` derives, from a regex's own parse tree, the literals it cannot
match without. A document missing one is never evaluated against that regex.
The derivation is a CNF: for an alternation it takes one clause from EVERY
branch and unions them, because a match could come through any of them.

That means a single branch which derives nothing drops the requirement for the
WHOLE regex. Every other branch in it, however selective, stops being skippable.
The rule then runs on every document, and any cost hiding in it is paid on every
document.

This is not hypothetical and it is not rare. The same shape produced three
different-looking defects in one week:

  GLS-ENC-ALT-210   a bare braille character class sat beside a base64 branch.
                    A 27 KB document that is one long word took 255 seconds,
                    because the rule could not be skipped on a document
                    containing neither "decode" nor "base64". Fixed by splitting
                    the alternatives into separate regex entries.
  #152 siblings     `api key` and `env var` begin with 3-character runs, under
                    MIN_LITERAL, so the whole secret-object class was
                    underivable and the rules ran on documents with no object.
  #149 destinations an email local part and a bare domain start with character
                    classes, so the destination class derived nothing.

Each was found by chasing a symptom. This finds the shape directly.

What it reports, and what it does not do
----------------------------------------
It lists every regex whose requirement is EMPTY but which has at least one
top-level branch that WOULD derive a clause on its own. Those are the ones where
splitting the alternation, or bounding the offending branch, buys the prefilter
back. It changes nothing and recommends nothing per rule: a branch that derives
nothing is often correct (a pure character class has no literal to give), and
whether to split is a judgement about that rule.

It deliberately calls the real `_prefilter` internals rather than re-implementing
the derivation. A report that models the deriver instead of asking it would
drift from the thing it is meant to describe, which is how the published numbers
came apart in the first place.

    python3 scripts/report_unskippable_rules.py            # print the report
    python3 scripts/report_unskippable_rules.py --json     # machine readable
    python3 scripts/report_unskippable_rules.py --count    # just the number
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sunglasses import _prefilter as pf          # noqa: E402
from sunglasses.patterns import PATTERNS         # noqa: E402

try:                                             # 3.11+ moved it
    import re._parser as sre_parse               # noqa: E402
except ImportError:                              # pragma: no cover
    import sre_parse                             # noqa: E402


def top_level_branches(parsed):
    """Every top-level alternation branch, descending through plain groups."""
    out = []
    for op, av in parsed:
        name = str(op)
        if name == "BRANCH":
            out.extend(av[1])
        elif name == "SUBPATTERN":
            out.extend(top_level_branches(av[-1]))
    return out


def _branch_literals(branch):
    """The clause this branch would contribute if it stood alone, or None."""
    return pf._pick(pf._clauses(branch))


def scan():
    findings = []
    for pattern in PATTERNS:
        for index, source in enumerate(pattern.get("regex") or []):
            try:
                if pf.requirement(source):
                    continue                     # already skippable, nothing to say
                parsed = sre_parse.parse(source, re.IGNORECASE)
            except Exception:                    # noqa: BLE001 — an unparseable
                continue                         # regex is a different problem
            branches = top_level_branches(parsed)
            if len(branches) < 2:
                continue                         # not an alternation, no branch to blame
            derivable, blind = [], 0
            for branch in branches:
                clause = _branch_literals(branch)
                if clause:
                    derivable.append(sorted(clause)[:6])
                else:
                    blind += 1
            if derivable:
                findings.append({
                    "id": pattern["id"],
                    "regex_index": index,
                    "branches": len(branches),
                    "would_derive_alone": len(derivable),
                    "blind_branches": blind,
                    "sample_literals": derivable[:3],
                })
    findings.sort(key=lambda f: (-f["would_derive_alone"], f["id"]))
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="machine readable output")
    ap.add_argument("--count", action="store_true", help="print only the count")
    args = ap.parse_args()

    findings = scan()

    if args.count:
        print(len(findings))
        return 0
    if args.json:
        print(json.dumps(findings, indent=2))
        return 0

    print(f"\n  Rules the prefilter cannot skip because one branch derives nothing")
    print(f"  {'─' * 68}")
    if not findings:
        print("  none\n")
        return 0
    for f in findings:
        print(f"  {f['id']:24} regex[{f['regex_index']}]  "
              f"{f['branches']:3} branches, {f['would_derive_alone']} would derive "
              f"alone, {f['blind_branches']} derive nothing")
        for literals in f["sample_literals"]:
            print(f"      would have required: {literals}")
    print(f"\n  {len(findings)} regex(es) across "
          f"{len({f['id'] for f in findings})} rule(s).")
    print("  Splitting an alternation into separate regex entries is usually enough;")
    print("  the engine ORs the entries and each one derives on its own.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
