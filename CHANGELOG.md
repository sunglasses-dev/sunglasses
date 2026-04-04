# Changelog

All notable changes to Sunglasses are documented here.

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
- Free and open source (AGPL-3.0)
- Local-first: no data leaves your machine
- Honest positioning: we acknowledge competitors and explain where we fit
