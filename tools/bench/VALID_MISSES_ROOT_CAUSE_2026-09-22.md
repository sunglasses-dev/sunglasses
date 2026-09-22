# The valid misses have ONE cause, and it is not the regex

Root-caused on main `ebb24fa`, channel `api_response`, from
`tools/bench/mcp_tool_description_bench.py`. Fifteen rules stayed silent on a
sample that matches their own predicate standalone. Classified:

| cause | count |
|---|---|
| **rule does not declare `api_response` at all** | **14** |
| detected but dedup-shadowed (content still blocked) | 1 |
| declares it, genuinely silent | 0 |

## The fourteen
`GLS-TP-001`, `GLS-TP-002`, `GLS-TP-ITDP-219/220/221/224` and the rest are
scoped to `message`, `file`, `web_content`, `tool_output`. **A `tools/list`
RESULT travels on `api_response`** (`selector.py` T2.R7). So the predicate
matches, the rule exists, and it is simply not wired to the channel where a
poisoned tool description actually arrives.

**This is not a detection gap in the pattern. It is a channel-declaration gap**,
and it is the same shape #170 already solved once: its `-API` siblings exist
because rules that should see the RESULT direction did not declare it. Its own
law fits here exactly — *a sibling copies the parent predicate character for
character and adds CHANNELS and nothing else.*

## The one that is not a miss
`GLS-TMS-253` DOES declare `api_response`, and it IS detected — it appears in
the raw `result.findings` and is then dedup-shadowed in favour of
`GLS-TMS-250`. The content is blocked; only the attribution differs. Counting
it as a miss would have been reading the wrong surface, which is a mistake this
lane has already made once: `.findings` is raw, `to_dict()` is what a consumer
sees, and they answer different questions.

## What I am NOT claiming
**That adding `api_response` to those fourteen is safe.** Widening a channel
widens exposure, and the false-alarm rate on `api_response` for these
predicates is UNMEASURED. The clean corpus here is ten hand-written
descriptions, which is a floor and not a guarantee. **Before any of this
ships, the FP sweep has to run on the real corpus for each candidate rule** —
that is the measurement #170's siblings had and this note does not.

## What this means for Jev idea #1
It sharpens the design question. Fourteen of the misses are closable by a
CHANNEL declaration, at authoring time, for free, with no model in the loop.
**Whatever Jev is for here, it is not those fourteen.** The honest scope of a
model pass is what remains after the channel wiring is fixed and re-measured —
and nobody knows that number yet, including me.

Recorded, not fixed. No rule changed. Branch only.
