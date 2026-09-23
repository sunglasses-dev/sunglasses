# TOOL-METADATA `-API` SIBLINGS @ `@HEAD@` — REVIEW PACKAGE
Base `@BASE@`. PR #230. **0.6.1, NOT Friday, NOT for merge before 0.6.0.**
Emitted by `tools/review/siblings/build-package.sh @HEAD@ @BASE@` from the two refs; §0 is `ROUND_NOTES.md` at the head.

@ROUND_NOTES@
## §1 WHAT THIS IS
Fourteen rules whose SUBJECT is a tool's advertised metadata did not declare
`api_response`. A `tools/list` RESULT travels on exactly that channel
(`selector.py` T2.R7). So the predicate matched, the rule existed, and it was
never asked the question where a poisoned tool description arrives.

Built by #170's law: **a sibling copies the parent predicate character for
character and adds CHANNELS and nothing else.**

## §2 DIGESTS
    head/ @HEAD_FILES@ files, name list IDENTICAL to @HEAD@ (symlinks counted, diffed
          against `git ls-tree -r`, not counted)
    base/ @BASE_FILES@ files, name list IDENTICAL to @BASE@
    head/sunglasses/patterns.py sha256 @PATTERNS_SHA@…

## §3 THE SPINE, AND WHY IT IS THE SPINE
**`p1` predicate parity · `p2` FP sweep · `p3` DETECTION · `p4` refusal names itself.**

Read `p2` and `p3` TOGETHER, because on their own they lie. **Two generators
were thrown away building this.** The second produced fourteen siblings that
loaded cleanly, carried the right ids, raised `len(PATTERNS)` by exactly 14 —
and matched NOTHING, because each regex was emitted as `r` plus its `repr`: a
raw string of an already-escaped repr, doubling every backslash.

**The FP sweep on that broken set came back a clean ZERO.** True, and
worthless: a rule that matches nothing has no false positives either. **A clean
FP number on a dead predicate is the most reassuring lie available.** Only
`p3` — do they DETECT — caught it, and that is why it is not a formality.

## §4 THE ROUND: ATTACK THE FOUR PROPERTIES
1. **Parity.** Is any sibling's predicate NOT its parent's, in a way `p1`
   cannot see? It compares `regex` and `keywords` lists; is there a field that
   changes behaviour and is not compared?
2. **Cost, ruled.** Attack the INHERITED claim, not the ruling: find a description a sibling blocks on
   api_response while its PARENT does not block it on any of the parent's own channels. That would be NEW cost,
   and it is the one thing the ruling does not cover.
3. **Coverage.** Eleven siblings NAME themselves; three are detected and
   dedup-shadowed behind other new siblings. Is "shadowed" really covered
   here, or does the shadowing hide a case where the shadowing rule would NOT
   have fired?
4. **Attribution.** `_deciding_rule_ids` takes the ids from the FIRST page that
   carried findings, deliberately not a union across pages. Construct a refusal
   where that first page is NOT the page a human would say caused it.

## §5 WHAT IS STATED RATHER THAN CLAIMED
- **Coverage 14/14, attribution 11/14.** Three are present in the raw findings
  and shadowed on the consumer surface. `result.findings` is raw,
  `to_dict()` is what a client sees, and they answer different questions.
- **GLS-TMS-253 is deliberately NOT here.** It already declares the channel and
  IS detected, merely shadowed behind GLS-TMS-250 — an attribution difference,
  not a miss.
- **The catalog counts move: engine 1565 → 1579, trusted 1591.** Published
  numbers. RS10's pin was re-counted by DIFFERENCING both catalogs against a
  detached worktree of `origin/main`, not by eye: added sets are exactly these
  fourteen ids, nothing removed, `helper_catalog` unmoved. SHIP_MANUAL 4.8a/4.8c
  says the gate decides the published figure, not a human.
- **END TO END, not just the engine:** 14 hostile listings driven through the
  real binary over a pty are refused `PROHIBITED_CONTENT` before reaching the
  client, with a CLEAN listing returning `APPROVAL_REQUIRED` as the control.
- **THE DEFECT ROUND 1 PINNED IS NOW FIXED, AND THAT IS THE NEW ROW.** The pin
  said a refused listing carried `rule_ids: []` and `inspected_utf8_bytes: 0`
  while `tools/call` named its rules. The cause was not the scan: **`_snapshot.
  collect` refuses a poisoned listing BEFORE the approval store is ever asked
  for a verdict**, and that return in `activation.py` dropped the ids already
  sitting in `found.page_scans`. The zero byte count is the same fact from the
  other side — those bytes are counted by the result-scan envelope, which this
  refusal never reaches. Ids now flow through `Activation`, `Outcome`,
  `_withhold` and the envelope. The pinned test is INVERTED: it now asserts the
  block names its rule. **`inspected_utf8_bytes` is still 0 on this path and is
  NOT fixed here** — say whether an envelope that names rules while reporting
  zero inspected bytes is coherent, or whether that number should be absent
  rather than zero.

## §5b THE ATTRIBUTION FIX IS SPLIT OUT, AND YOUR RULING BINDS BOTH
The attribution fix in §5 also lives on `fix/listing-refusal-names-its-rule`
(PR #231, head `adee5d4` at round 1 — **#231 has since MERGED to main as `09feb44`**), because THIS branch moves a
published rule count and cannot merge before 0.6.0, while that one adds no rule
at all. **RE-MEASURED 2026-09-23 against the MERGED `09feb44`, paths checked to exist in both refs:** `activation.py`,
`approvals.py`, `route.py`, `echo_server.py` and `regex_sample.py` diff to ZERO lines; the end-to-end test differs
by 37 changed lines, which is the filter/row difference described at the end of this section. At round 1 it read:
**The six files are byte-identical across the two heads** —
`activation.py`, `approvals.py`, `route.py`, `echo_server.py`, the end-to-end
test and `regex_sample.py` all diff to zero lines; only `patterns.py`, the
attack-db entries and the two count pins differ. So your ruling on §4 item 4
and on §5 is the ruling for #231 as well, and it is what gates that merge.

**AND ONE OF THEM WOULD HAVE MERGED BLIND.** The end-to-end test renders its
triggers from the rule DB and filtered them to the three families THIS branch
adds. On a branch cut from main that filter matches nothing — main has fourteen
`-API` rules and none are in those families — so every row skipped AND THE
CONTROL SKIPPED WITH THEM, on a message that reads like information. The filter
is gone on both branches; here that is 15 rows rather than 14, there it is one
row plus a control that actually runs. Say whether rendering a trigger from the
rule's own predicate is sound at all, or whether a rule that samples its own
regex can only ever prove it matches itself.

## §6 YOUR ITEMS
0 read this (incl. §0) · 1 confirm §2 · 2 `p1-predicate-parity.sh` · 3 `p2-fp-sweep.sh` ·
4 `p3-detection.sh` · 5 `p4-refusal-names-its-rule.sh` · 6 the proxy rows in
`tests/proxy/test_poisoned_listing_end_to_end.py` · 7 attack §4 · 8 rule on §5.
