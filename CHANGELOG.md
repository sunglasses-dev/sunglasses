# Changelog

All notable changes to Sunglasses are documented here.

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
