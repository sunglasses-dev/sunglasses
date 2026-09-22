# Six attack-db descriptions our own scanner blocks — classified

Found while building the MCP tool-description bench, on main `ebb24fa`,
channel `api_response`. Measured, not inferred:
`python3 tools/bench/mcp_tool_description_bench.py --show-misses`

| record | blocked by | kind |
|---|---|---|
| GLS-TMS-244 | **itself** | self |
| GLS-TMS-246 | **itself** | self |
| GLS-TMS-254 | **itself** | self |
| GLS-TP-006 | GLS-MECH-006 | other |
| GLS-TP-ITDP-226 | GLS-TD-002 | other |
| GLS-TMS-240 | GLS-MECH-001 | other |

## What they are
**All six are PROSE ABOUT an attack. None carries a payload.** They open
"Attacker exploits permissive schema-drift fallback chains…", "Detects
tool-description poisoning that frames weakened controls as…". They describe a
mechanism in the same vocabulary the rule matches, which is the whole of why
they fire. Three trip their OWN regex; three trip a different rule's.

So they are false positives on our own documentation — and the attack-db is
PUBLISHED, so anyone who scans our published attack database with our scanner
gets six blocks.

## What NOT to do, and this is the point
**Do not reword the descriptions.** Editing documentation until a scanner stops
objecting is the "widen until the corpus passes" anti-pattern with the arrow
reversed: the text is correct, and the docs would be made worse to flatter the
tool.

**Do not add a runtime carve-out.** That door was closed on 9-21: every
value-driven exclusion on GLS-SD-010-EMB was defeated by attacker-chosen bytes,
and the KNOWN_FAILURES ruling put it in writing — the arbiter is AUTHORING-TIME,
never a runtime unblock.

## What these are actually for
This is precisely the describes-versus-performs class. The Jev study reports
that a "describes vs performs an attack" question **"clears all 6 known FPs,
holds 6/6 attacks, margin 0.72"**.

**Six.** I cannot prove these are the same six — the study's corpus is in no
file on this machine, which is the same gap the bench had to route around —
but the count matches, the class matches, and they are the six sitting in our
own repository. **If the authoring-time arbiter is built, this is its first
target set, and it is already measured and named.**

The useful property: the arbiter would tell us WHICH REGEX to loosen, at
authoring time, with a human deciding. That is a different act from a runtime
gate changing block to allow, and it is the only version the runtime rule
permits.

## Status
Recorded, not fixed. No rule changed, no description reworded. Branch only.
