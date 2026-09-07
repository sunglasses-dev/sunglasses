# Known Version Gaps

Quick FYI: an audit on May 6, 2026 surfaced some historical gaps in this project's version history. We fixed what was fixable and documented the rest.

## What we found

- 9 PyPI versions were never published (7 pre-launch + `0.2.27` and `0.2.30` which failed silent uploads)
- 8 git tags were missing for shipped versions

## What we did

- **Tags:** all 8 missing tags were created retroactively pointing at the right commits, then pushed.
- **PyPI gaps:** left as-is. `pip install sunglasses` works fine; retroactive uploads with stale code would create more confusion than they resolve.

## Going forward

- Pre-flight gate blocks any new ship that would skip a patch number.
- Daily 6 AM PT integrity check audits PyPI ↔ git tags ↔ CHANGELOG ↔ live site and surfaces drift before it builds up.

## Allowlist (machine-readable — integrity check parses these)

PyPI versions accepted as not-published:
- pypi-gap: 0.2.1
- pypi-gap: 0.2.2
- pypi-gap: 0.2.3
- pypi-gap: 0.2.4
- pypi-gap: 0.2.7
- pypi-gap: 0.2.8
- pypi-gap: 0.2.9
- pypi-gap: 0.2.27
- pypi-gap: 0.2.30

Pre-launch tags accepted as not-recovered:
- tag-gap: 0.1.0
- tag-gap: 0.1.1
- tag-gap: 0.2.0
- tag-gap: 0.2.5
- tag-gap: 0.2.6

To allowlist a future gap, add a `- pypi-gap: X.Y.Z` or `- tag-gap: X.Y.Z` line above and re-run the integrity check.

---

# Known Capability Gaps

Version gaps above are about release history. This section is about the
product: things the scanner and firewall **do not do**, that a reasonable
person might assume they do. It exists because the failure mode this project
cares most about is a tool that reports a clean result for something it never
actually inspected — and silence about a limitation is its own version of that.

## v0.5.6 — the firewall is best-effort on very long unbroken tokens

**What.** The pattern matcher's cost is roughly linear in input length for
ordinary whitespace-separated text, and roughly **quadratic** for a single
unbroken token — a base64 blob, a `data:` URI, a minified bundle line, a long
hex string or JWT.

The growth is measurable and reproducible; the exact byte counts and timings are
held in our internal release evidence rather than published here, so this file
states the boundary without also handing over a tuned recipe. The fix lands in
v0.6 and the measurements go public with it.

**Why it matters, beyond speed.** The PreToolUse firewall hook has a 10-second
timeout, and Claude Code does not treat a timed-out hook as a block: *"A
timed-out command hook doesn't block the tool call. The call continues through
the normal permission flow."* So an input of this shape can push the hook past
its timeout, and the tool call then proceeds **unscanned**. That is reachable from attacker-controlled input, which makes it
a bypass of the enforcement surface rather than a performance complaint. The
same curve stalls a repo scan in CI.

**What the input cap does and does not do.** `MAX_SCAN_BYTES` is 1 MB. It bounds
the LENGTH of the input; it does not bound the cost, because the cost is
quadratic *in* that length for this input shape.

**Why no test caught it.** `tests/test_input_cap.py::test_truncation_bounds_the_cost`
exists to prove exactly this, and builds its payload as `"a " * n` — the
whitespace-separated shape, which is the fast one. The gate has been green
throughout while the quadratic shape was unbounded underneath it.

**Status.** Not fixed in v0.5.6. v0.5.6 is a scoped trust repair, and the fix
belongs in the matcher; landing it unreviewed at the end of a repair release is
the kind of change this release exists to avoid. A ratio-based regression test
(`test_engine_cost_is_linear_only_for_whitespace_separated_input`) documents the
curve without asserting a wall-clock ceiling. Being fixed in v0.6, along with a
bounded mitigation so that an unscannable input shape fails **visibly** instead
of failing open.

**Until then:** treat the firewall as best-effort on inputs containing very long
unbroken tokens. The static scanner still does not execute scanned content;
this is about what gets inspected, not about what runs.

## v0.5.6 — a boundary-assertion defect leaves some pattern branches unreachable

A `\b` written immediately before a literal that is not a word character (`-`,
`.`, `/`) can never assert after whitespace, so the alternative behind it never
matches. A static sweep of the pattern database finds **198 unreachable
alternatives across 89 patterns** (175 high, 13 medium, 10 critical severity).

Four were repaired in v0.5.6, including `GLS-EX-007`, where *every* alternative
began with `-` — that pattern matched nothing at all from 2026-04-08 until this
release. After that repair **no pattern is wholly unreachable**; the remaining
89 still fire on their other branches, so the effect is that those rules are
quietly narrower than they read.

A full sweep, and a permanent gate that makes this class un-shippable, is a v0.6
item.

## v0.5.6 — the published evidence database lags the shipped engine

`attack-db/` is generated from `sunglasses/patterns.py` by
`scripts/export_patterns_to_attack_db.py`, and has not been regenerated in some
time: re-running it rewrites 51 existing files and creates 409 that were never
exported. Nothing was regenerated in v0.5.6 (a 460-file diff inside a scoped
repair release would not have been reviewable). The engine is the source of
truth; treat `attack-db/` as a lagging mirror until v0.6 re-syncs it and gates
it.

## v0.5.6 — the pin consent gate is at the command, not in the library

`sunglasses pin` asks before starting your MCP servers. That gate lives in the
CLI (`_pin_run`), so a Python caller that imports `sunglasses.firewall` and calls
`probe_server()` or `build_pins()` directly still spawns the configured servers
with no prompt.

The CLI is the only shipped surface that reaches those functions (verified: their
only callers are inside `firewall.py` and `cli.py`), so nothing we distribute
launches a server unasked. But the boundary is real, it is not covered by the
consent tests, and anyone embedding the library should know where the gate is
before assuming they inherited it. Moving the gate into the library is a v0.6
item; it changes a public API signature, which a scoped repair release is the
wrong place for.

## v0.5.6 — `--repo` skips an oversized file where `--file` scans the first MiB

Both surfaces report their coverage honestly, and neither reports a false clean.
They just do not read the same bytes:

* `sunglasses scan --file big.txt` scans the first 1 MiB and reports
  `truncated: true`, `inspection_complete: false` — so a finding in the first KB
  of a 1.1 MB file is **found**, alongside an explicit statement that the rest was
  not read (exit 1).
* `sunglasses scan --repo <repo>` skips any member over the 1 MB walker limit
  entirely, names it in `skipped` with the reason, and reports the run as
  incomplete (exit 3) — so the same injection in the same file is **not found**.

The consequence worth stating plainly: an attacker who pads a poisoned file past
1 MB is invisible to a repository scan while remaining visible to a direct file
scan of that same file. The repo scan does say the file was not inspected, so a
consumer that reads `skipped` is not misled — but a consumer that reads only the
exit code learns "incomplete", not "there is an injection in here".

Not changed in v0.5.6 on purpose: unifying them changes what the walker reads on
every large file in every repository, which is a behaviour and performance change
rather than a trust repair, and this release is scoped to the latter. The
divergence is asserted as the current behaviour in the acceptance matrix
(`cli_repo` / `truncated + finding`, carried as a note rather than hidden in an
N/A) so a later change has to update a test that says what it used to do.
Unification is a v0.6 item.
