# GLS-SD-010-EMB @ `@HEAD@` — REVIEW PACKAGE
Base `@BASE@`. Release: 0.6.1 (T11 count rule, 9-23: Friday ships without this rule).
**Round 11 is the FINAL round for this rule (T9 RULING 32).** A NO GO parks it in the 0.6.2 backlog; there is no round 12.
Emitted by `tools/review/sd010/build-package.sh @HEAD@ @BASE@` — every file here comes from the two refs plus that script.

## §1 WHAT THE RULE IS
A detection rule for a `NAME=value` assignment that sits INSIDE structured text (a JSON string, a dict literal, a
YAML line). Round 10 (T9 ruling 13) stopped adding escapes one review at a time: the rule is now held to a TABLE.
`tests/sd010_escape_grammar.py` lists every escape of JSON, Python and YAML 1.2 double-quoted strings (one character,
`\xNN`, `\uNNNN`, `\UNNNNNNNN`, octal, `\N{name}` with its aliases, escaped line breaks), checks each spelling
against `json.loads`, `ast.literal_eval` and `yaml.safe_load`, and generates cases in five positions (boundary,
indentation, after an escaped newline, separator, the `=` itself), each with a lowercase control.
**Round 11 (T9 RULING 32), your round 10 finding.** The four `\N{...}` name scopes were `(?i:...)`, which under
Unicode matching also equates U+0130, U+0131, U+017F and U+212A with ASCII letters, so `\N{L<U+0130>NE FEED}` read as a
line feed. They are `(?ai:...)` now: case-insensitive, ASCII only. And the matrix no longer relies on spellings a review
found. It asks the regex engine which codepoints fold to an ASCII letter, over all of Unicode, respells every table
name with each (family `name case fold`), swaps the case of every letter introducer (`\X0a`, `\U000a`,
`\n{LINE FEED}`, family `introducer case`), and records what the real decoders read for each. 619 derived spellings,
10590 cases in all. A family classifier written apart from the grammar module diffs the matrix against your round 10
probe families; against the round 10 grammar module it reported 12 probes in families the matrix lacked.
**The contract:** the rule reports iff the RAW text or the text with the escape DECODED would report under the
literal rule — boundary (start of text, the `str.splitlines` set, or one of `" ' { [ ,`), indentation (space, tab),
the upper-case name, separator (`\s`), `=`. It is syntax-blind: a spelling that is an escape in any of the three
grammars counts everywhere. Disclosed consequence: the r9 row `r9_python_escaped_space_indent` now BLOCKS, because
backslash-space is YAML's escaped space.
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
    …through p9. A probe's EXIT CODE is its result: 0 pass, non-zero fail.

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
| p9-decode | NEW (RULING 32): what JSON, Python and YAML each read for a spelling, by codepoint, decoded independently of the grammar module, beside where the matrix stands on it. Runs your round 10 probes by default and every fenced ```decode block in VERDICT.md. Fails when the matrix and the decoders disagree, or when the engine's fold set differs from the enumerated one |

## §4 YOUR OWN CASES — the part that has found the most
Write them in VERDICT.md as fenced ```case blocks of JSON:
`{"name": "...", "expect": "block" | "allow", "why": "...", "text": "...", "channel": "file"}`.
Use the placeholders `{NAME}` `{NAME_LC}` `{VALUE}` `{URL}` for the assignment's parts; p7 expands them and marks
those rows `[template]`. A block that does not parse is reported and not scored.

**The axis that found the most in earlier rounds is the QUOTING and ENCODING context around the assignment, not the
value.** The escape grammar is now a table, so the productive question is what the TABLE is missing:
an escape it does not list, a position it does not generate, or a decoder that disagrees with it. Find one and the
matrix is wrong, not just the rule. `tests/test_sd010_escape_grammar.py` is the table's own test file.

**To ask a decoder about a spelling** (round 10 could not), write a fenced ```decode block in VERDICT.md:
`{"name": "...", "spelling": "\\N{LINE FEED}"}` (JSON string escapes: a backslash twice, a non-ASCII letter as
`\uXXXX`), then run `zsh @OUT@/probes/p9-decode.sh`. It prints codepoints only.

## §5 WHAT IS STATED RATHER THAN CLAIMED
- **No value-based exception exists.** Exceptions keyed on the value were a closed class: each was defeated by a
  chosen value. `DISCLOSED_MISSES` is empty and a test asserts it.
- **One accepted ledger row:** `sunglasses-dev__env-var-docs-shapes.md` is blocked by this rule, booked in
  KNOWN_FAILURES with a reason and a ruling. `p3` reports it as accepted.
- **Escapes are read by table, not decoded.** Every escape of a boundary, indentation, separator or `=` character,
  in every spelling the three grammars have, is in the rule; the matrix holds it there (0 of 10590 disagree on every
  channel) and 20 in-memory controls plus the `p4` variants V15–V22 each remove one family and watch it go red.
  V22 puts Unicode folding back in the name scopes.
  **Residual, by decision:** an escape INSIDE the name's letters (`API\x5fKEY=`). The name is a literal alternation;
  decoding it is the parser this rule is not. **Bound, disclosed:** the boundary and indentation escape sets are
  disjoint by construction — a spelling in both would make a run of it quadratic.
- The consumer surface shadows this rule on the parent's three channels; `to_dict()` dedupes and is what CLI, API and
  SARIF show. Every probe that inspects a finding reads it; `p5` measures timing and inspects none.
- Cost ratio stated by `p5` against its gate; pattern count 1554 → 1555.
- **The prefilter cannot skip this rule**: the boundary alternatives carry no literal. It holds a measured allowlist
  entry (`tests/test_prefilter_branch_coverage.py` KNOWN_UNSKIPPABLE, receipt `tests/perf_receipts/GLS-SD-010-EMB.json`
  bound to the engine sha): four shapes at 1 MiB, each ≤ 2.0x against the engine without the rule, with both worst-case
  families recorded in the receipt. Its exit is a 0.6.2 row: derivable literals, then remove the entry.

## §6 YOUR ITEMS
0 read this · 1 confirm §2 · 2 p1 · 3 p2 · 4 p3 · 5 p4 · 6 p5 · 7 p6 · 8 p8 · **9 p7 with your own cases** · 10 rule on §5 ·
11 p9, and a ```decode block for any spelling whose reading you want settled before you rule on it.
