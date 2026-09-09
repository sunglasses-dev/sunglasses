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

**Shape sensitivity at a FIXED length, measured 2026-09-07 on the release head.** The
README's "~50 µs/byte" is a floor, not a rate that holds across inputs. Six payloads, each
just over the 1 MiB cap so each scans exactly the capped 1,048,576 bytes, warm engine,
same machine:

| payload shape | wall clock |
|---|---|
| `" " * n` (a run of spaces) | 51.8 s |
| `"." * n` | 52.9 s |
| `"benign filler. " * n` (ordinary prose) | 66.6 s |
| `"filler line\n" * n` | 73.8 s |
| `"a " * n` | 111.0 s |
| `"\n" * n` (a run of newlines) | 139.8 s |

Same byte count, **2.7× spread**. This is the ordinary-shape band and it does not include
the unbroken-token case above, which is the quadratic one. It is recorded because the
README previously stated the linear rate without qualification, and because a reader
sizing a CI budget from "50 µs/byte" would be wrong by a factor of three before ever
meeting an adversarial input. No tuned recipe is published here for the same reason as
above.

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

## v0.5.6 — Languages: the shipped coverage is English-first, and "23 languages" was not true

The README claimed 23 languages in four places. That number counted every language *named*
anywhere in the ruleset as though it were covered. Measured against `sunglasses/patterns.py`
at this release:

| tier | count | languages | what actually exists |
|---|---|---|---|
| full ruleset | 1 | English | all 1,540 patterns |
| dedicated patterns | 13 | Spanish, Portuguese, French, German, Russian, Turkish, Arabic, Chinese, Japanese, Korean, Hindi, Indonesian, Vietnamese | **exactly 2 patterns each**: an "ignore previous instructions" injection and one credential-exfiltration shape |
| keyword-level only | 7 | Italian, Dutch, Ukrainian, Polish, Czech, Azerbaijani, Hebrew | keywords appear inside English-scoped patterns; **no dedicated pattern** |
| named only | 2 | Persian, Bengali | **no dedicated pattern and no keyword** — listed as covered, present nowhere |

How to reproduce both halves:

```sh
# dedicated patterns per language: 13 languages x 2
grep -oE '"([A-Z][a-z]+)-language' sunglasses/patterns.py | sed 's/"//; s/-language//' | sort | uniq -c
# keyword presence for a named language (Persian and Bengali return nothing)
grep -c 'نادیده\|دستورالعمل' sunglasses/patterns.py
grep -c 'উপেক্ষা\|নির্দেশ' sunglasses/patterns.py
```

Two patterns is a seed, not coverage: it catches the single most literal phrasing of one attack
and nothing else, so a non-English deployment should not be assumed to have English parity. The
normalization layer (romanization, Unicode confusables, 17 other obfuscation techniques) is
language-independent and does apply everywhere.

Nothing about detection changed here — no pattern was added, removed or edited for this entry.
Only the claim was corrected. Deepening real coverage is a v0.6+ lane, and it needs per-language
false-positive corpora before per-language claims: a language whose false-positive rate we cannot
measure separately is a language we cannot honestly advertise.

**Related correction in the same sweep:** the README's keyword count read **6,642**. Measured at
this release it is **6,944 unique keywords** (7,683 entries summed across patterns). The old
figure predates the +80 patterns that landed in v0.5.4. Pattern count (1,540) and category count
(118) were both verified correct and are unchanged.

## v0.5.6 — what "every document carries the three axes" is scoped to

The release notes and README say a SUNGLASSES scan document carries `threat_found`,
`inspection_complete` and `is_clean`. That sentence is true of every surface enumerated
in `V056_ACCEPTANCE_MATRIX.md` — 28 surfaces × 12 input states, each asserted by a test
in `tests/test_v056_matrix.py` — and it is scoped to those rows deliberately.

ASTRA's third review refused the unqualified version of the claim, and was right to: at
that point the five public extractor `scan_*` convenience functions and the three retained
`SunglassesScanner` helpers had no rows, and two of them were returning documents with no
axes at all. They have rows now, and the defects are fixed. But the honest form of the
claim names its scope, because the argument that made it false once is available again the
moment somebody adds a surface without adding a row.

**Outside the matrix, and therefore outside the claim:**

- Anything a caller builds themselves from `engine.ScanResult` attributes. The object
  carries the axes as properties; a dict a caller assembles by hand does not, unless it
  goes through `sunglasses.result.normalize()`.
- `sunglasses.firewall`'s hook verdicts. That surface answers allow/deny/defer for a tool
  call, not a coverage question, and it has its own gap entry above.
- `engine.info()`, `check`, `version` and the other non-scan commands.

**How to check the claim rather than take it:** `python3 -m pytest tests/test_v056_matrix.py`
runs one test per asserted cell. `python3 tools/gen_v056_matrix_table.py` regenerates the
table from the same module the tests parametrize over, so the table cannot claim a cell the
suite does not assert. Note what that does NOT prove: a generated table proves the table and
the tests read one source, not that the tests assert anything. That is what the 18 mutation
cases in the same file are for — each feeds a response with its coverage evidence stripped
to the same assertion functions the real cells use and requires it to FAIL.

## v0.5.6 — three input states that now answer differently

Behaviour changes, not bug fixes, and each is a matrix state:

**Non-regular inputs are refused (`nonregular`).** A FIFO, socket, device node or directory
at the input path is an operational error — CLI exit 2, MCP `isError: true`, library
`NonRegularFile` (a subclass of `UnreadableFile`, so existing handlers already catch it).
Previously the readability probe proved a path readable by OPENING it, and opening a FIFO
with no writer blocks in the kernel: an MCP `scan_file` on a named pipe never returned at
all. The type check now happens on `os.stat` metadata, before any file object exists.
Note the consequence: `scan --file /dev/null` is now exit 2, where an empty regular file is
exit 0. A device is not a thing we can scan; an empty file is.

**A byte stream that does not decode is incomplete, never clean (`undecodable`).** Every
text read was `open(..., errors="ignore")`, which silently DROPS undecodable bytes: a
256-byte file of non-UTF-8 pairs scanned 128 bytes and returned `inspection_complete: true,
is_clean: true`. We still scan what decodes — throwing the file away would lose real
coverage — but the answer is exit 3 and the warning names how many bytes went unread.
Latin-1 text and mislabelled binaries land here. Valid UTF-8 is unaffected.
On stdin the answer is different because the transport is: undecodable stdin is an
operational error (exit 2, one document), not a partial scan. Decoding with replacement
there would mean reporting on a substitution the caller never sent.

**Empty input is complete and clean (`empty`).** `--text ""`, empty stdin, an empty file and
MCP `scan_text` with an empty string all return exit 0, `inspection_complete: true`,
`is_clean: true`, `bytes_scanned: 0`. Nothing went unread, so nothing was hidden — this is
the one case where "we inspected all of it" costs nothing and is exactly true. Both human
renderings say `0 bytes inspected — the input was empty` rather than `No threats detected`,
so a reader can tell a clean scan of a document from a clean scan of nothing. MCP keeps one
distinction the CLI cannot express: a MISSING `text` argument is still a usage error, because
the tool's API contract was broken and nothing was submitted; an empty string is content.

## v0.5.6 — three silent skips outside the scan path, reported and not fixed

Round 4 removed every silent `except: pass` in `sunglasses/extractors/` that could cost scan
coverage (the receipt is a checker, not a grep: it walks the AST for exception handlers whose
whole body is `pass`/`continue`, and the only two that survive are temp-file cleanups where
failing to delete a scratch file loses nothing). Sweeping the rest of the package turned up
three more, all in DIAGNOSTIC commands rather than in a scan:

- `cli.py:1030` — `sunglasses check` skips a `settings.json` it cannot parse.
- `cli.py:1039` — the same command skips a hook command it cannot lex.
- `cli.py:1085` — `sunglasses receipts` skips a receipt line that is not valid JSON.

They are the same *shape* as the defects this release fixes — a thing we could not read, passed
over without saying so — and in the first two cases that means `check` can report a healthy
firewall while sitting next to a settings file it never managed to read. They are NOT fixed here
for one reason: this release is scoped to what a SCAN reports about content, the acceptance matrix
covers scan surfaces, and widening it to the diagnostic commands at the end of a repair release is
the kind of unreviewed change the release exists to avoid. They are recorded so the next round
starts with them on the list rather than rediscovering them.

## v0.5.6 — `--repo` skips most of the formats `--file` extracts, and not consistently

MEASURED, not described. The repository walker declines members by extension
(`cli.py::_BINARY_EXTENSIONS`); the file path routes by CONTENT
(`extractors/dispatch.py::identify`). Crossing the two lists:

| formats the extractor routes | in repo mode |
|---|---|
| `.bmp` `.gif` `.jpeg` `.jpg` `.pdf` `.png` `.webp` | **skipped and named** — never reach the extractor |
| `.tif` `.tiff` | **scanned** — they are absent from the walker's skip list |

So an instruction hidden in a committed **PNG's** EXIF, a **GIF's** later frame, or a
**PDF's** annotations is reported by `scan --repo` as uninspected scope (exit 3, the member
named), and by `scan --file <member>` as a finding (exit 1). The same instruction in a
committed **TIFF** is found by both — the walker's list simply never included `.tif`.

That inconsistency is not a second bug on top of the first; it is the evidence that the two
lists were written independently and never reconciled, which is the same shape as audit
finding C1 (two file-scanning surfaces, two extension tables, opposite answers) one level
up. C1 was fixed by giving both surfaces one owner; the walker was not part of that fix.

**Why it is a gap and not a false clean:** every skipped member is named, in every output
format (`skipped`, `notInspected`, and the human `INCOMPLETE SCAN` list), and the scan exits
3, not 0. Nothing claims to have read them. As of round 5 the skip line also says what to do
about it — `Scan it directly to look inside: sunglasses scan --file <path>` — because
"binary file type (.gif) — not inspected" told a reader what happened and not what closes it.

**Why it is deferred:** reconciling the lists means the walker runs OCR over every committed
image, which changes what a repo scan costs (seconds per image, per frame) and what it
promises. That is a scope decision with a performance budget attached, taken deliberately in
v0.6, not a coverage repair made at the end of a repair release.

**Reproduce:** commit a GIF whose second frame carries an instruction and a TIFF whose
ImageDescription carries the same one; `scan --repo` finds the TIFF and names the GIF as
skipped, `scan --file` finds both.
