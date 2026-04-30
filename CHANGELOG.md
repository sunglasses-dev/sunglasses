# Changelog

All notable changes to Sunglasses are documented here.

## [0.2.26] — 2026-04-29

### Added
- **16 new patterns, all in `cross_agent_injection`** — patterns: 413 → **429** (+16). Categories unchanged at **54**. Keywords unchanged at **2,296**.
  - GLS-CAI-622 — `forged_scheduler_receipt_scope_override_guardrail_bypass`
  - GLS-CAI-682 — support-bundle/ticket-attachment prompt-swap chain-of-command bypass
  - GLS-CAI-623 — forged safety/audit attestation bypass of validators
  - GLS-CAI-624 — peer-agent forged authorization bypass
  - GLS-CAI-625 — forged human-override scope escalation
  - GLS-CAI-627 — `forged_quorum_ack_scope_override_guardrail_bypass`
  - GLS-CAI-582, GLS-CAI-528 — historical CYCLE imports normalized into the CAI prefix
  - GLS-CAI-628, 629, 630, 632 — forged delegation/handoff variants
  - GLS-CAI-563, GLS-CAI-555, GLS-CAI-552, GLS-CAI-561 — additional cross-agent forged-receipt classes
- All patterns HIGH severity, validated TP=8 / TN=8, 0 false positives.

### Context
- One-category-per-day shipping rule locked in — every v0.2.X push from now on focuses one attack class so the day's release + blog tell one story. v0.2.26 = `cross_agent_injection`. Companion blog: `/blog/a2a-trusted-handoff-override` (Jack byline, original Cycle 181 evidence).
- Source pool: `~/jack-harvest/ready/v0.2.26_ready.json`. 19 staged → 3 dropped (empty regex) → 16 shipped.

## [0.2.22] — 2026-04-25

### Added
- **Day 2 of v0.2.21–v0.2.27 drip series** — daily 15-pattern releases continuing.
- **16 new patterns across 9 categories** — patterns: 346 → **362** (+16). Categories: 50 → **51** (+1 NEW).
  - **NEW CATEGORY** `state_sync_poisoning` — **GLS-SSP-001 / GLS-SSP-532 / GLS-SSP-539**. Forged checkpoint / replica / state-sync receipts that bypass policy gates, validation, and integrity checks during reconciliation. Distinct from `tool_output_poisoning` (forges the *content* of a tool result) — SSP attacks the *integrity signal* on stateful sync between agents.
  - `tool_output_poisoning` (3) — GLS-TOP-001, GLS-TOP-250, GLS-TOP-259.
  - `model_routing_confusion` (2) — GLS-MRC-252, GLS-MRC-528.
  - `cross_agent_injection` (2) — GLS-CAI-533, GLS-CAI-584.
  - `error_message_leakage` (2) — GLS-EML-251, GLS-EML-252.
  - `policy_scope_redefinition` (1) — GLS-PSR-002.
  - `dns_tunneling` (1) — GLS-DN-578.
  - `retrieval_poisoning` (1) — GLS-RP-526.
  - `invisible_unicode` (1) — GLS-IU-531.
- All 16 patterns are HIGH severity (state_sync_poisoning, tool_output_poisoning, cross_agent_injection, model_routing_confusion, policy_scope_redefinition, dns_tunneling, retrieval_poisoning, invisible_unicode); error_message_leakage is medium.
- Each pattern validated against TP=8 / TN=8 fixtures (Jack-curated synthetic test set), 0 false positives.

### Operations
- Removed orphan blog `opus-4-7-effort-levels-broke-my-flow.html` (pulled from blog index Apr 25, archived to `~/Desktop/orphan-blog-archive/` for future repurpose).

### Maturity signals
- 7/7 pytest passing · SARIF 2.1.0 output · MIT licensed · zero API keys · zero telemetry.
- 5 public Anthropic CVP benchmark runs (full Anthropic family scoreboard: Opus 4.7, Opus 4.6, Sonnet 4.6, Haiku 4.5).

---

## [0.2.21] — 2026-04-24

### Added
- **Day 1 of v0.2.21–v0.2.27 drip series** — 7 consecutive daily releases with 1-2 category launches per day. SEO+AEO play: each day gets its own launch blog (JACK byline) to build ranking momentum across the "agent security" keyword surface.
- **18 new patterns across 13 categories** — patterns: 328 → **346** (+18). Keywords: 2,160 → **2,296** (+136). Categories: 49 → **50** (+1 NEW).
  - **NEW CATEGORY** `agent_contract_poisoning` — **GLS-ACP-001 / GLS-ACP-566 / GLS-ACP-567**. Attacks that poison the contract/schema/interface between agents, rebinding precedence and bypassing guardrails via forged SLA exceptions, contract appendices, or runbook clauses. Distinct from `cross_agent_injection` (hostile message *content*) — ACP attacks the *shape* of the agent-to-agent contract itself.
  - `tool_output_poisoning` (2) — 2 new ACP-adjacent forgery patterns.
  - `retrieval_poisoning` (2) — RAG integrity / ranked-doc override variants.
  - `cross_agent_injection` (2) — peer-handoff + delegation-chain variants.
  - `memory_eviction_rehydration` (1), `dns_tunneling` (1), `c2_indicator` (1), `prompt_extraction` (1), `provenance_chain_fracture` (1), `policy_scope_redefinition` (1), `agent_persona_drift` (1), `rtl_obfuscation` (1), `code_switching` (1).
- 18 high severity (no critical this drop).

### Operations
- `/IDnormalization` skill added — canonical `GLS-<PREFIX>-<NNN>` enforcement at every ship. Prefix map at `.claude/skills/IDnormalization/scripts/prefix_map.json`.
- Jack source-of-truth system live — `JACK_PATTERN_DB_REFERENCE.md` auto-regenerates into Jack's Docker after every ship. First `HARVEST_FEEDBACK.md` delivered — Jack now sees which patterns shipped, held, or failed validate (with reasons).
- Research feeds wired for Jack — daily 06:00 UTC cron pulls NVD CVEs + arXiv cs.CR papers + MITRE ATLAS + OWASP LLM Top 10. 561 external research files now feeding novel-primitive generation.

### Context
- Pattern pool state: 97 tonight-validated patterns + 233 historical-backfill patterns = **330 ship-ready patterns queued** across Days 2-7 (Apr 25-30) and beyond.
- Live Attack Experiment scheduled Apr 28 — Day 5 bundle lands before experiment kicks off so the treatment arm runs on current scanner.

### Maturity signals
- 7/7 pytest passing · SARIF 2.1.0 output · MIT licensed · zero API keys · zero telemetry.
- 2 public Anthropic CVP benchmark runs against Claude Opus 4.7 (Apr 17 + Apr 20); Run 3 queued post-drip.

---

## [0.2.20] — 2026-04-22

### Added
- **15 new patterns across 7 categories** — tail of Apr 20 held pool. Patterns: 313 → **328** (+15). Keywords: 2,019 → **2,160** (+141). Categories: 49 (unchanged — no new category this beat).
  - `retrieval_poisoning` (3) — **GLS-RP-252 / GLS-RP-253 / GLS-RP-254**. Further RAG integrity hardening (doc-rank override, citation-checksum bypass, seed-loop variants).
  - `token_smuggling` (3) — **GLS-TS-254 / GLS-TS-255 / GLS-TS-256**. Frontmatter role priority smuggle follow-ons + hidden policy-tag variants.
  - `tool_chain_race` (3) — **GLS-TCR-248 / GLS-TCR-251 / GLS-TCR-252**. Out-of-order revocation ack replay, ordered-state leak pushes.
  - `tool_output_poisoning` (2) — **GLS-TOP-245 / GLS-TOP-247**. Spoofed tool-result variants.
  - `tool_metadata_smuggling` (1) — **GLS-TMS-236**. Signed-envelope authority policy override.
  - `prompt_injection` (1) — **GLS-PI-20**. Semantic-indirect-injection via navigation-constraint reframing.
  - `tool_poisoning` (2) — **GLS-TP-ITDP-253 / GLS-TP-ITDP-254**. Audit-log suppression justifications + environment-equivalence provenance-waiver.
- All 15 high severity.

### Context
- Close-out ship for the 25-pattern pool held from v0.2.18 release cadence. First 10 shipped in v0.2.19 (with new category `policy_scope_redefinition`); remaining 15 ship here to clear the queue before the drip cadence begins.
- **CHANGELOG note:** This entry was backfilled on 2026-04-24 after AZ noticed the v0.2.20 commit (`19b21aa`) updated README + setup.py but skipped CHANGELOG.md. Root cause: `/ship` skill had no CHANGELOG step. A `preflight-changelog.sh` check was added as part of v0.2.21 to block future ships if CHANGELOG doesn't match `__version__`.

### Maturity signals
- 7/7 pytest passing · SARIF 2.1.0 output · MIT licensed · zero API keys · zero telemetry.

---

## [0.2.19] — 2026-04-21

### Added
- **10 new patterns across 10 categories** — patterns: 303 → **313** (+10). Keywords: 1,919 → **2,019** (+100). Categories: 48 → **49** (+1 NEW).
  - **NEW CATEGORY** `policy_scope_redefinition` — **GLS-PSR-001** (Governance Appendix Precedence Override). Covers attacks that reinterpret scope boundaries after agent authorization.
  - `cross_agent_injection` — **GLS-CAI-248** (Delegation Token Revocation Ignore Verification Bypass). **CRITICAL severity.**
  - `retrieval_poisoning` — **GLS-RP-251** (Seeded Feedback Loop Rank Override Guardrail Evasion).
  - `tool_output_poisoning` — **GLS-TOP-244** (Tool Output Poisoning).
  - `tool_chain_race` — **GLS-TCR-247** (Ordered State Leak Push).
  - `token_smuggling` — **GLS-TS-252** (Frontmatter Role Priority Smuggle).
  - `agent_persona_drift` — **GLS-APD-250** (Unrestricted Role Override).
  - `supply_chain` — **GLS-SC-20** (Dependency Trust Bypass).
  - `parasitic_injection` — **GLS-PA-2** (Hidden Annotation Payload Policy Override).
  - `tool_metadata_smuggling` — **GLS-TMS-235** (Tool Metadata Smuggling Directive).
- 1 critical severity + 9 high severity.

### Context
- Released the 10 patterns staged in `v0219_hold_for_later.json` (held back from v0.2.18 for fact-check pass and staggered release cadence).
- `policy_scope_redefinition` is the first new attack-category class shipped since v0.2.18's 7-category wave (retrieval_poisoning, cross_agent_injection, social_engineering_ui, model_routing_confusion, tool_output_poisoning, memory_eviction_rehydration, tool_chain_race).
- Jack's cycles 411–428 (Apr 21) add further pattern candidates — held for v0.3.0 / v0.3.1.
- v0.3.0 "Construct" launch deferred — originally planned as hybrid cascade engine (Layer 1 patterns + Layer 2 DistilBERT + Layer 3 LLM Judge), Layers 2 and 3 still in build. v0.3 ships when cascade is real.

### Maturity signals (unchanged from v0.2.18)
- 7/7 pytest passing · 64/64 internal recall · SARIF 2.1.0 output · MIT licensed · zero API keys · zero telemetry.
- 2 public Anthropic CVP benchmark runs against Claude Opus 4.7 (Apr 17 + Apr 20).

## [0.2.18] — 2026-04-20

### Added
- **34 new patterns across 12 categories** — largest pattern dump since launch. Patterns: 269 → **303**. Keywords: 1,603 → **1,919** (+316). Categories: 48 (unchanged — PSR held for v0.2.19).
  - `retrieval_poisoning` (7) — **GLS-RP-245 through GLS-RP-250, GLS-RP-255**. Covers RAG integrity attacks: citation-ranked source authority flip, instruction priority laundering, consensus citation override, verification bypass priority escalation, confidence badge source check bypass, source checksum mismatch ignore provenance gate, cache manifest hash bypass.
  - `cross_agent_injection` (6) — **GLS-CAI-242 through GLS-CAI-247**. A2A trust-boundary attacks: peer-to-peer trust rebind override, fabricated quorum bypass, forged policy checkpoint waiver, delegated attestation replay guardrail bypass, approver identity swap bypass, forged handoff authority ack (human-authority spoofing).
  - `social_engineering_ui` (4) — **GLS-SUIEI-234 through GLS-SUIEI-237**. Visual-injection lures: device code reauth banner, MFA push-fatigue loop, WebAuthn passkey fallback downgrade, DevTools cookie export lure.
  - `model_routing_confusion` (3) — **GLS-MRC-248, GLS-MRC-249, GLS-MRC-250**. Tier spoof/shadow router/forged model card tier escalation bypasses.
  - `tool_output_poisoning` (3) — **GLS-TOP-246, GLS-TOP-248, GLS-TOP-249**. Forged verification stamps, confidence banner tamper, forged checksum log integrity gate bypass.
  - `memory_eviction_rehydration` (3) — **GLS-MER-236, GLS-MER-237, GLS-MER-238**. Checkpoint reset hidden rehydrate bypass + eviction/rehydration override variants.
  - `tool_chain_race` (2) — **GLS-TCR-249, GLS-TCR-250**. Ordered tool state leak push, concurrent approval timeout escalation.
  - `exfiltration` (2) — **GLS-EX-18, GLS-EX-19**. Output channel exfiltration via timing error partial secret probe and stream timing error sidestream.
  - `token_smuggling` (1) — **GLS-TS-253**. Frontmatter role priority smuggle.
  - `multi_stage_encoding`, `parasitic_injection`, `provenance_chain_fracture` — 1 pattern each.
- 316 new compound-phrase keywords (hardened against single-word false-positive traps per v0.2.17 lesson).
- 23 critical severity + 11 high severity = **34 patterns total**.

### Held for v0.2.19+ (25 patterns)
- 25 additional patterns extracted + EDGE-reviewed but held to stagger release cadence and allow keyword hardening + fact-check pass. Includes 2 `NEEDS_REVIEW` patterns from Jack's pool and the new `policy_scope_redefinition` category (GLS-PSR-001) which will ship as its own beat.

### Research source
- Base pool: 287 Jack candidate files across 16 categories in `~/jack-data/patterns/`.
- Dedup pipeline (agent-driven): identified 48 SAFE + 21 EDGE. 10 EDGE promoted after Sonnet review. Net selection: 59 → 34 shipped today.
- 3 SUIEI patterns (GLS-SUIEI-234/235/236) recovered from CYCLE45 batch that was initially mis-clustered during dedup. Manual add after spot-check verified novelty vs shipped 9 SUIEI patterns.

### Infrastructure
- New HARD RULE: never stage multi-hour autonomous work in `/tmp` — macOS wipes on reboot. All work now goes to `~/<project>-staging/`. See `feedback_never_write_work_to_tmp.md`.
- v0.2.17 `/tmp` artifacts from overnight autonomous run vaporized at reboot Apr 20 morning — 80% recovered via session JSONL scrape; new staging discipline prevents recurrence.

## [0.2.17] — 2026-04-19

### Added
- **10 new regex patterns across 5 NEW categories and 3 existing** — biggest category growth since v0.2.14:
  - `tool_chain_race` (NEW CATEGORY) — **GLS-TCR-245** (ordered handoff policy bypass) + **GLS-TCR-246** (handoff ack bypass window). First coverage for timing / ordering attacks on agent tool chains and handoffs.
  - `model_routing_confusion` (NEW CATEGORY) — **GLS-MRC-247** — "switch to cheaper/smaller model to bypass safety/guardrails" attack pattern targeting the model-router / effort layer. Directly relevant to Auto Mode and Opus 4.7 multi-tier routing.
  - `context_flooding` (NEW CATEGORY) — **GLS-CF-248** — eviction-via-padding attacks: flooding the context window with repeated/duplicated tokens to push earlier guardrails / system prompts out of the window.
  - `agent_persona_drift` (NEW CATEGORY) — **GLS-APD-249** — gradual multi-turn persona/tone/behavior drift with stealth instructions. Distinct from one-shot jailbreak_roleplay — targets the slow-drift surface in long conversations.
  - `error_message_leakage` (NEW CATEGORY) — **GLS-EML-250** — forced-error attacks: deliberately trigger/force/induce errors or stack traces to leak system prompt / hidden instructions / API keys / tokens.
  - `token_smuggling` — **GLS-TS-251** — injection via HTML / code / YAML comment channels and metadata annotation fields that most agents treat as non-instructional.
  - `prompt_injection` — **GLS-PI-018** (typoglycemia override variant) + **GLS-PI-019** (encoded payload decode-and-execute). Covers scrambled-character and base64/hex/rot13-encoded instruction smuggling.
  - `tool_poisoning` — **GLS-TP-ITDP-252** — compliance / legal / audit pretext used to justify disabling PII redaction and exporting unredacted data.
- 10 new regex patterns, ~80 new keywords
- Patterns: 259 → **269** | Keywords: 1,523 → **1,603** | Categories: 42 → **48**

### Changed
- **README truth-layer reconciliation** — reconciled README claims against actual code / stats. Corrected: test count (now shows 64/64 internal recall + 7 pytest, previously claimed made-up "66/66"), pattern/keyword/language/category counts (now pulled from `stats/current.json`), scan speed (now shows verified avg 0.26ms on M3 Max), throughput (now shows verified 3,830/sec single-threaded), and local-only claim (now qualified with opt-in Resend email note).
- **Version drift fix** — `sunglasses/mcp.py` `SERVER_VERSION` was pinned at `0.2.4` for 12 releases; now imports dynamically from `sunglasses.__version__`. Single source of truth.

### Research source
10 patterns derived from Jack's autonomous pattern-extraction work across CYCLE38, CYCLE49, CYCLE62, CYCLE192, CYCLE193, CYCLE232, CYCLE233, CYCLE234, CYCLE237, CYCLE266. All validated CLEAN or with TP/TN ≥ 8/10 on fixture sets before integration. Triage performed and documented in `jack-patterns-triage-v0217-2026-04-18.html`.

### Blog
- New blog post: **"A2A lets agents talk. Sunglasses decides whether they should be trusted to act."** — draft authored by Cava (Director of Threat Intelligence), published alongside this release. Frames cross-trust-boundary risk as the core thesis for Sunglasses v0.3 direction.

## [0.2.16] — 2026-04-18

### Added
- **4 new regex patterns across 3 existing categories** — depth expansion after Anthropic's Claude Code Auto Mode launch highlighted trust-boundary adjacent surfaces:
  - `cross_agent_injection` — **GLS-CAI-241** — forged, spoofed, replayed, fabricated, or stolen approval tickets / signoff receipts / delegation tokens from an upstream, downstream, peer, or delegate agent used to justify bypassing scope, boundary, permission, policy, guardrail, or verification controls. Ticket-forgery variant of A2A trust handoffs.
  - `retrieval_poisoning` — **GLS-RP-242** — retrieved RAG chunk, search index note, knowledge base snippet, or document-store record carrying a provenance disclaimer, footer annotation, watermark warning, or metadata note, but claiming authoritative / canonical / source-of-truth status to override current policy, guardrails, or verification.
  - `tool_output_poisoning` — **GLS-TOP-243** — tool output, execution summary, result payload, agent report, or response digest reporting a signature mismatch, checksum failure, hash mismatch, or verification failure, then instructing the agent to ignore the execution / verification gate and run, deploy, or proceed anyway. "Failure-as-license" execution-gate bypass.
  - `retrieval_poisoning` — **GLS-RP-244** — retrieval result, source snippet, document excerpt, knowledge chunk, or indexed source surfacing a lineage, provenance, citation, source-integrity, or origin warning, and instructing the agent to suppress or bypass the warning and execute, apply, or publish anyway. Suppression-of-warning attack surface in RAG pipelines.
- 4 new regex patterns, 32 new keywords
- Patterns: 255 → 259 | Keywords: 1,491 → 1,523 | Categories: 42 (unchanged)

### Research source
Patterns derived from Jack's autonomous pattern-extraction cycles CYCLE287–CYCLE290 (Apr 18). All four validated against fixture sets before integration: 8/8 positive-match on CYCLE288 / CYCLE289 / CYCLE290, 7/8 on CYCLE287 (regex widened to also cover "another agent" / "peer agent" phrasing). 0 false positives across all benign fixture sets.

## [0.2.15] — 2026-04-17

### Added
- **2 new threat categories** covering multi-agent and RAG pipelines:
  - `cross_agent_injection` — **GLS-CAI-239** — upstream/previous/delegated agent output claimed as trusted, authoritative, verified, signed, or approved is used to justify ignoring system prompt, policy, guardrails, or instructions. Covers A2A (agent-to-agent) trust-boundary abuse in multi-agent workflows.
  - `retrieval_poisoning` — **GLS-RP-240** — retrieved document, knowledge-base chunk, or top-ranked search result presented as authoritative / ground truth is used to justify overriding system instructions, policy, or safety rules. Covers retrieval-time injection in RAG pipelines.
- 2 new regex patterns, 16 new keywords
- Patterns: 253 → 255 | Keywords: 1,475 → 1,491 | Categories: 40 → 42

### Research source
Patterns derived from Jack's autonomous pattern-extraction work (CYCLE181 + CYCLE184), validated CLEAN (FP=0, FN=0) on reference corpus of 12 and 16 cases respectively. Both cover attack surfaces explicitly flagged as uncovered in the internal pattern database reference.

## [0.2.13] — 2026-04-15

### Added
- **SARIF 2.1.0 output support.** `sunglasses scan --output sarif` emits a fully spec-conformant SARIF log, compatible with GitHub Advanced Security code scanning, CI/CD gates, and any SARIF-aware dashboard.
- `to_sarif()` and `to_sarif_json()` public API in `sunglasses.sarif` for programmatic use.
- Per-finding `security-severity` scores (0.0–10.0) for GitHub Advanced Security severity triage.
- Rule deduplication: identical rules across multiple scan results appear only once in `tool.driver.rules`.
- `columnKind: utf16CodeUnits` for correct GitHub GHAS column rendering.

## [0.2.3] — 2026-04-04

### Added
- **3 new agent workflow security patterns (batch 2)** — expanding coverage of agentic content automation threats.
  - GLS-AW-004: Poisoned persistent prompt or skill (critical) — malicious instructions hidden in saved skills, playbooks, or persistent memory
  - GLS-AW-005: Poisoned RSS or brand doc ingestion (high) — external feeds/docs containing hidden directives treated as trusted planning material
  - GLS-AW-006: Unsafely auto-published marketing content (critical) — generated content pushed live without human review or validation
- 36 new keywords and 6 new regex patterns
- Patterns: 72 → 75 | Keywords: 406 → 442 | Categories: 18 (unchanged)

### Research source
Patterns derived from CAVA's continued analysis of real-world agentic SEO/content automation workflows, focusing on persistence attacks, poisoned ingestion pipelines, and missing approval gates.

## [0.2.2] — 2026-04-04

### Added
- **New threat category: `agent_workflow_security`.** 3 patterns targeting AI agent-to-tool pipeline attacks — a class of threats no other scanner covers.
  - GLS-AW-001: Web fetch to publish pipeline injection (critical)
  - GLS-AW-002: Overprivileged CMS publish connector (critical)
  - GLS-AW-003: Overprivileged social scheduler connector (high)
- 36 new keywords and 6 new regex patterns for detecting agent workflow abuse
- Patterns: 69 → 72 | Keywords: 370 → 406 | Categories: 17 → 18

### Research source
Patterns derived from CAVA's analysis of real-world agentic SEO/content automation workflows, cross-referenced with OWASP LLM01 and published prompt injection research.

## [0.2.1] — 2026-04-04

### Fixed
- **Attack database now ships in pip packages.** Previously, `attack-db/` JSON files were only available in the git repo but missing from wheel and sdist builds. `pip install sunglasses` users calling `load_attack_db()` got an empty result. The 15 threat patterns are now packaged inside `sunglasses/data/attacks/` and the loader finds them automatically in both installed and repo layouts.
- **Broken README links removed.** `GOVERNANCE.md` and `registry/` were referenced but never existed. Replaced with links to the thesis page and `attack-db/` directory.
- **Fixed setup.py project URL.** "Threat Registry" pointed to a nonexistent `registry/` path. Updated to "Threat Database" pointing to `attack-db/`.

### How we caught it
Our security research agent (CAVA) audited the built release artifacts and found 0 attack-db files in both wheel and sdist. The repo claimed to ship a threat database — but the package didn't. For a security product, that gap is unacceptable. We fixed it the same day.

## [0.2.0] — 2026-04-03

### Added
- 8 new detection patterns: prompt extraction, encoding evasion, invisible Unicode, indirect prompt injection
- 36 new keywords across all pattern categories
- 4 new threat categories: `prompt_extraction`, `encoding_evasion`, `invisible_unicode`, `indirect_prompt_injection`
- Threat-intel-derived patterns from real-world attack analysis (HuggingFace datasets, OWASP, published research)

### Fixed
- All `glasses[...]` install references updated to `sunglasses[...]` across 7 files
- Version synced: `__init__.py` matched to `setup.py` (was 0.1.0, now 0.2.0)
- Added `extras_require` for optional dependencies (image, pdf, qr, audio, video, all)
- Added `conftest.py` with pytest `engine` fixture
- Extractors `__init__.py` updated from "coming soon" to actual descriptions
- Added `MANIFEST.in` for source distribution

## [0.1.1] — 2026-04-02

### Added
- 8 supply chain attack patterns
- Real-world validation: scanned actual North Korean malware (BlueNoroff/Lazarus axios RAT)
- 3 threats caught in 3.67ms — published as first vulnerability report

## [0.1.0] — 2026-04-01

### Added
- Initial release
- 53 prompt injection detection patterns
- 334 keywords, 13 categories
- FAST and DEEP scan modes
- CLI: `sunglasses check "text"` and `sunglasses scan file.txt`
- Negation-aware context (warnings about attacks don't trigger false positives)
- 66/66 tests passing

### Philosophy
- Free and open source (MIT License)
- Local-first: no data leaves your machine
- Honest positioning: we acknowledge competitors and explain where we fit
