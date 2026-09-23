<!-- The per-round section of the emitted MANIFEST (§0). REWRITE it for each round: what moved since the
     reviewer's last verdict. build-package.sh inserts it verbatim; everything else in MANIFEST is the template. -->
## §0 WHAT CHANGED SINCE ROUND 2 (`cba2251` → `685d992`, ONE commit)
- **Your HOLD is resolved by ruling, not by narrowing.** T9 ruled: your defensive-documentation description is
  blocked regardless of framing, because a tool listing is attacker-controlled text and "training tool" is the costume
  an attacker writes. No predicate narrowing (a sibling is its parent's predicate character for character, the #170
  law) and no exemption for security prose (an off switch the attacker holds).
- **MEASURED: the cost is INHERITED, not new.** On current main `1cae43a` (parents untouched by this branch) the same
  text is ALLOWED on api_response and already BLOCKED on `file` by exactly the two parents, GLS-TP-ITDP-226 and
  GLS-TMS-234, and on tool_output / web_content / message by those and other rules.
- **Booked** in `tests/test_tool_metadata_siblings_ruled_cost.py`: the ruled set on api_response is pinned, and every
  firing sibling's parent must fire on `file`, so a sibling that ever fires where its parent does not reads as NEW
  cost. Control: both rows FAIL on main's code, pass on head. Deliberately NOT in `fp_real_world_corpus`, which feeds
  the published precision benchmark as real famous-repo READMEs.
- **Your reproducibility finding is fixed:** the builder copies the probes and `regex_sample.py` from the EXTRACTED
  HEAD TREE, and REFUSES (exit 3) a ref without them instead of `|| true`. This package was built that way.
- **NOT in this commit:** your §8 zero-byte ruling (omit `inspected_utf8_bytes` on the listing-refusal path). It is
  with T9 as a separate row and is not claimed here.
