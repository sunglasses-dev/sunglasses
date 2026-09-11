#!/usr/bin/env python3
"""Refuse to publish a tree that CI did not fully verify.

Until 2026-09-10 the release path had no mechanical gate. `/ship` asked a human
whether to upload, and a human looking at a green-ish checks list cannot tell
the difference between "the matrix passed", "the matrix was skipped because the
change looked like documentation", and "the run was cancelled and nothing ever
reported". PyPI is immutable, so that difference only becomes visible after it
cannot be taken back.

This asks the one question that matters and answers it from the API rather than
from a summary line: did the FULL matrix run and succeed, on this exact commit?

Every failure mode here is a refusal. A missing run, an in-progress run, a
skipped leg, a cancelled leg, an API error, an unparseable reply -- none of
those are evidence that the work was done, and the absence of evidence is
exactly what this exists to catch.

    python3 scripts/require_release_certification.py <sha> [--repo owner/name]

Exit 0 only when the tree is release certified. Anything else exits non-zero
with the reason on stderr.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

WORKFLOW = "pattern-integrity"

# The legs that must have RUN and SUCCEEDED for a tree to be publishable.
# `integrity` is a matrix, so its legs are matched by prefix.
REQUIRED_EXACT = {"classify", "fast", "coverage", "certify"}
REQUIRED_MATRIX_PREFIX = "integrity"
REQUIRED_MATRIX_LEGS = 6          # 3.9 through 3.14


def refuse(reason: str) -> None:
    print(f"RELEASE REFUSED: {reason}", file=sys.stderr)
    raise SystemExit(2)


def gh_json(args: list[str]):
    try:
        out = subprocess.run(["gh", *args], capture_output=True, text=True,
                             timeout=60)
    except FileNotFoundError:
        refuse("the gh CLI is not installed, so certification cannot be checked")
    except subprocess.TimeoutExpired:
        refuse("the GitHub API did not answer within 60s")
    if out.returncode != 0:
        refuse(f"gh {' '.join(args[:2])} failed: {out.stderr.strip()[:300]}")
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        refuse("the GitHub API reply was not JSON; refusing to guess")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sha", help="the exact commit being released")
    ap.add_argument("--repo", default="sunglasses-dev/sunglasses")
    args = ap.parse_args()

    if len(args.sha) < 7:
        refuse(f"{args.sha!r} is not a commit sha")

    runs = gh_json(["run", "list", "--repo", args.repo,
                    "--workflow", f"{WORKFLOW}.yml", "--limit", "60",
                    "--json", "databaseId,headSha,status,conclusion,event"])

    mine = [r for r in runs if r.get("headSha", "").startswith(args.sha)
            or args.sha.startswith(r.get("headSha", "")[:7])]
    if not mine:
        refuse(f"no {WORKFLOW} run exists for {args.sha[:12]} — "
               "an unverified tree is not publishable")

    # Prefer a completed run; a later in-progress rerun must not mask an
    # earlier verdict, and an in-progress-only result is not certification.
    completed = [r for r in mine if r.get("status") == "completed"]
    if not completed:
        refuse(f"the {WORKFLOW} run for {args.sha[:12]} has not finished "
               f"(status={mine[0].get('status')}) — running is not passing")

    run = completed[0]
    if run.get("conclusion") != "success":
        refuse(f"run {run['databaseId']} concluded {run.get('conclusion')!r}")

    detail = gh_json(["run", "view", str(run["databaseId"]), "--repo",
                      args.repo, "--json", "jobs,headSha"])
    if not detail.get("headSha", "").startswith(args.sha[:7]):
        refuse("the run returned a different head sha than requested")

    jobs = detail.get("jobs") or []
    if not jobs:
        refuse("the run reports no jobs at all")

    by_name = {}
    for j in jobs:
        by_name.setdefault(j.get("name", ""), []).append(j)

    problems = []
    for name in sorted(REQUIRED_EXACT):
        found = [j for n, js in by_name.items() if n == name for j in js]
        if not found:
            problems.append(f"{name}: never ran")
            continue
        for j in found:
            if j.get("conclusion") != "success":
                problems.append(f"{name}: {j.get('conclusion') or j.get('status')}")

    legs = [j for n, js in by_name.items()
            if n.startswith(REQUIRED_MATRIX_PREFIX) for j in js]
    if len(legs) < REQUIRED_MATRIX_LEGS:
        problems.append(
            f"{REQUIRED_MATRIX_PREFIX}: {len(legs)} legs ran, "
            f"{REQUIRED_MATRIX_LEGS} required — a skipped leg is not a pass")
    for j in legs:
        if j.get("conclusion") != "success":
            problems.append(f"{j.get('name')}: {j.get('conclusion') or j.get('status')}")

    if problems:
        refuse("this tree is not release certified:\n  " + "\n  ".join(problems))

    print(f"RELEASE CERTIFIED: {args.sha[:12]} — run {run['databaseId']}, "
          f"{len(REQUIRED_EXACT)} jobs + {len(legs)} matrix legs all green")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
