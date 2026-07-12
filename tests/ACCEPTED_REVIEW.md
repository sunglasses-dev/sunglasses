# Accepted known-review residue — AZ decision, 2026-07-11

The FP carrier-anchor sprint (Jul-11 2026) drove the famous-README ratchet
from **72 → 9** blocking files. The remaining 9 in `KNOWN_FAILURES.json` are
**AZ-accepted as "flagged for review," not defects to keep grinding.**

## Why these 9 are different from the 34 we cleared

Each remaining file is *domain-inherent*: the pattern that fires shares its
entire subject with the file's actual topic, so the co-occurrence signal is
real vocabulary, not a regex bug.

| File | Offenders | Why it's inherent |
|---|---|---|
| trufflesecurity/trufflehog | 11 | A secrets-scanner README literally documents the exfil/credential/advisory threat lexicon. |
| openai/openai-python | 9 | Dense AI-API client — agents, tools, tokens, models throughout. |
| langgenius/dify, run-llama/llama_index, ggml-org/llama.cpp, pytorch | 2–3 | AI frameworks that legitimately discuss agents, OpenAPI servers, model tokens, build metadata. |
| axios | 1 | GLS-DFP-018 is HTTP-**header** poisoning; axios is an HTTP library. |
| modelcontextprotocol/servers | 1 | GLS-MCP-016 is MCP-descriptor poisoning; this is the MCP servers repo. |
| redis | 1 | GLS-DFP-036 (CSAF/VEX advisory) co-occurs with redis's security section. |

## The decision (option 3 of 3 offered to AZ)

Ship v0.3.0 with these 9 as **known-review**. The /scan demo UI shows every
verdict with its matched signal + a "report a false positive" row, so these
read as *"flagged for review — here's why,"* never a naked red block. The 34
mainstream repos anyone would actually paste into the demo are already clean.

Rejected alternatives: (a) keep surgically tightening — diminishing returns and
real over-fit risk on 9 specific files; some (HTTP-header-on-HTTP-lib) are
unwinnable without gutting the pattern. (b) demote severity to quarantine on
long docs — heavier systemic change, deferred.

## Ratchet meaning going forward

> Note: this file lives at `tests/` root, NOT inside `tests/fp_real_world_corpus/`
> — the ratchet test scans every `.md` in that folder, and this doc's own attack
> vocabulary would (correctly) trip the scanner. Keep it out of the corpus dir.

`KNOWN_FAILURES.json` still only shrinks: if a future pattern change makes one
of these 9 scan clean, its entry MUST be deleted (the gate fails until it is).
These 9 are the accepted floor, not a to-do list.
