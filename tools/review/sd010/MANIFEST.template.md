# GLS-SD-010-EMB @ `@HEAD@` — REVIEW PACKAGE
Base `@BASE@`. Release: 0.6.0 if this round is GO and the PR is green by Thu 9-24 18:00, otherwise 0.6.1.
Emitted by `tools/review/sd010/build-package.sh @HEAD@ @BASE@` — every file here comes from the two refs plus that script.

## §1 WHAT THE RULE IS
A detection rule for a `NAME=value` assignment that sits INSIDE structured text (a JSON string, a dict literal, a
YAML line). It fires when the assignment starts at a boundary:
start of text · newline · literal CR · escaped `\n` / `\r` · U+2028 / U+2029 · one of `" ' { [ ,`
— each optionally followed by indentation, where indentation is a space, a tab, or an escaped `\t`.
Between the name and the `=`, the separator admits any whitespace `\s` matches OR its escaped two-character
form `\t` `\n` `\r` `\f` (added after round 7, which found the escaped tab there; the other three measured open too).
The name alternation is case-sensitive (inline `(?-i:)`, because the engine compiles with IGNORECASE).
**The value is not inspected at all.** A bare space and a backtick are NOT boundaries.
Declared channels (eight): message, file, code, api_response, log_memory, agent_input, tool_output, web_content —
the last two added after round 7; `p2` reads the list from the rule itself.

## §2 DIGESTS
    head/ @HEAD_FILES@ files, list identical to @HEAD@ (symlinks counted, no caches)
    base/ @BASE_FILES@ files, list identical to @BASE@
    head/sunglasses/patterns.py sha256 @PATTERNS_SHA@…

## §3 HOW TO RUN — by path only
Every probe is a script under `probes/`. Run each BY PATH and redirect its output to `logs/`:

    zsh @OUT@/probes/p1-baseline.sh      > @OUT@/logs/p1.out 2>&1
    …through p8. A probe's EXIT CODE is its result: 0 pass, non-zero fail.

Do not print probe sources; this manifest says what each one measures.

| probe | measures |
|---|---|
| p1-baseline | the rule fires on its reference set at head and not at base |
| p2-matrix | the fixture matrix: must-fire, benign, and disclosed rows |
| p3-sweep | specificity over the real-world corpus; an ACCEPTED ledger row is separated from an UNBOOKED cost, and only the latter fails |
| p4-variants | sensitivity of the test file: pre-built trees under `v/` (listed in `v/INDEX.json`), one unchanged control plus one per guard, each missing that guard. The control must be green; each variant must be DETECTED (pytest rc 1 AND a failed-test line) |
| p5-ratio | timing ratio against the gate |
| p6-robustness | six historical rows, each closed at head and reopened by its own designated variant |
| p7-constructed | cases YOU write in VERDICT.md: `zsh @OUT@/probes/p7-constructed.sh value --cases-from-verdict` |
| p8-modes | the rule under each evaluation mode |

## §4 YOUR OWN CASES — the part that has found the most
Write them in VERDICT.md as fenced ```case blocks of JSON:
`{"name": "...", "expect": "block" | "allow", "why": "...", "text": "...", "channel": "file"}`.
Use the placeholders `{NAME}` `{NAME_LC}` `{VALUE}` `{URL}` for the assignment's parts; p7 expands them and marks
those rows `[template]`. A block that does not parse is reported and not scored.

**The axis that found the most in earlier rounds is the QUOTING and ENCODING context around the assignment, not the
value.** Find another family of inputs the rule misses, or show that a closed shape is closed
only for the exact form that was tested. Round 7's family is now closed; its rows are in the test file.

## §5 WHAT IS STATED RATHER THAN CLAIMED
- **No value-based exception exists.** Exceptions keyed on the value were a closed class: each was defeated by a
  chosen value. `DISCLOSED_MISSES` is empty and a test asserts it.
- **One accepted ledger row:** `sunglasses-dev__env-var-docs-shapes.md` is blocked by this rule, booked in
  KNOWN_FAILURES with a reason and a ruling. `p3` reports it as accepted.
- **Six decoding shapes are out of scope, by decision:** JSON `\uXXXX` escapes of `=`, newline, space and tab, one
  nested escape, and one YAML sequence shape. Closing them means decoding string escapes before matching — a parser,
  not a boundary.
- The consumer surface shadows this rule on the parent's three channels; `to_dict()` dedupes and is what CLI, API and
  SARIF show. Every probe that inspects a finding reads it; `p5` measures timing and inspects none.
- Cost ratio stated by `p5` against its gate; pattern count 1554 → 1555.
- **The prefilter cannot skip this rule**: the boundary alternatives carry no literal. It holds a measured allowlist
  entry (`tests/test_prefilter_branch_coverage.py` KNOWN_UNSKIPPABLE, receipt `tests/perf_receipts/GLS-SD-010-EMB.json`
  bound to the engine sha): four shapes at 1 MiB, each ≤ 2.0x against the engine without the rule, with both worst-case
  families recorded in the receipt. Its exit is a 0.6.2 row: derivable literals, then remove the entry.

## §6 YOUR ITEMS
0 read this · 1 confirm §2 · 2 p1 · 3 p2 · 4 p3 · 5 p4 · 6 p5 · 7 p6 · 8 p8 · **9 p7 with your own cases** · 10 rule on §5.
