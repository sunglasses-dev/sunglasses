# GLS-SD-010-EMB review harness

The probes that produced the round 1–4 verdicts for `GLS-SD-010-EMB`, living
beside the rule they grade instead of in a tmp directory.

    tools/review/sd010/build-package.sh <head-ref> <base-ref> [out-dir]
    zsh <package>/probes/p1-red-control.sh            # …p8

| probe | asks |
|---|---|
| p1 | does BASE reproduce the gap — nothing else counts until it does |
| p2 | the fixture matrix across every declared channel |
| p3 | the FP corpus sweep, separating an ACCEPTED ratchet row from an UNBOOKED cost |
| p4 | the mutation battery against PRE-BUILT trees; an unmutated control gates it |
| p5 | the added cost, as a RATIO, with the number printed |
| p6 | the historical evasions, each reopening under its DESIGNATED mutant |
| p7 | cases CONSTRUCTED from axes, plus `--cases` for reviewer-authored ones |
| p8 | the `(?-i:)` scope in every evaluation mode, read back from the engine |

## ADDRESS THE PACKAGE AS `/tmp`, NEVER `/private/tmp`

The reviewer runs under `sandbox: workspace-write [workdir, /tmp, $TMPDIR]`,
and that writable root is matched as the LITERAL STRING `/tmp`. The resolved
spelling `/private/tmp` is the SAME DIRECTORY and gets a different answer: the
reviewer's SHELL works there, so every probe runs and every log lands, but its
EDITOR refuses the path as "outside of the project" — so it can measure
everything and still be unable to write a verdict.

**Round 5 was REFUSED for exactly this and nothing else.** Every probe was
green (red control 29/29, matrix 37/37, sweep 77 with 1 accepted and 0
unbooked, mutations 9/9 with control, ratio 1.01x, evasions 6/6, modes 4/4).
The round eleven minutes later, same design and same tree, wrote its verdict
without trouble because it happened to use `/tmp`. Nothing about the design was
wrong; the spelling was a coin flip and it landed badly once.

So the builder defaults to `/tmp`, and **every prompt must say the directory as
`/tmp/...` and tell the reviewer in one line that the editor rejects
`/private/tmp`** — because a reviewer that is refused a write will spend the
whole round before discovering it, and a blocked round costs the same window as
a real one.

## What the harness learned the hard way

- **No wrapper states a count.** Numbers in comments went stale twice and were
  claimed fixed once while still wrong. A driver prints what it DERIVED.
- **Every probe's exit code is its verdict.** Several printed a failure and
  exited 0.
- **A kill is `rc == 1` AND a failed-test line.** Any-non-zero counted a
  crashed harness as a kill.
- **The reviewer writes nothing.** Mutants are pre-built trees, verified on
  disk at build time; a driver that edited the tree under review was correctly
  refused.
- **Read the mode back from the engine.** p8 reports UNMEASURED when a
  synthetic rule does not land in the mode it was built for — which happened.
- **`to_dict()` is the consumer surface**; `.findings` is the raw list. A probe
  reading the wrong one overstates the rule.
- **An impossible PASS is a harness defect** exactly like an impossible fail.
