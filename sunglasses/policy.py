"""
policy.py — the policy layer between detections and decisions.

    "The engine reports findings. A single policy layer decides the action
     per surface and mode. BLOCK is only shown where we actually block
     model input."                          (verdict redesign, Jul 17 2026)

The engine finds evidence; this module turns evidence into an action, and the
right action depends on the surface:

  ENFORCEMENT surfaces (paste/message scan, runtime guard, CLI, strict CI)
  sit on the model-input boundary — content either enters the agent context
  or it doesn't. `decide_enforce` keeps the original worst-severity mapping,
  byte-identical: BLOCK there is honest.

  DISPLAY surfaces (repo scan, reports) describe risk in mixed content —
  README prose, dev docs, examples, configs. A repo is not a prompt, so
  `rollup_repo` grades on a ladder instead of crowning the worst file:

    clean                           no findings
    clean_notes                     findings worth showing, none corroborated
    review_before_agent_ingestion   2+ independent same-category high+ regex-
                                    confirmed findings in one file
    known_attack                    a curated Tier-S signature matched

Tier-S (`TIER_S_SIGNATURE_IDS`) is the ONLY route to a red verdict and ships
empty: every entry must be hand-curated (real exfil endpoints, encoded
payloads, known campaign strings). An ordinary pattern can never paint red,
no matter how it matches.
"""

from .patterns import PATTERNS

# ── Enforcement surface (model-input boundary) ──────────────────────────────

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "review": 0}

SEVERITY_TO_DECISION = {
    "critical": "block",
    "high": "block",
    "medium": "quarantine",
    "low": "allow_redacted",
    "review": "allow_redacted",
}


def decide_enforce(findings: list) -> str:
    """Worst-severity decision for enforcement surfaces (legacy behavior)."""
    if not findings:
        return "allow"
    worst = max(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 0))
    return SEVERITY_TO_DECISION.get(worst["severity"], "quarantine")


# ── Tiers ────────────────────────────────────────────────────────────────────

# Tier-S: curated known-attack signatures — the only red-capable set.
# Empty until a human reviews an entry in; see module docstring.
TIER_S_SIGNATURE_IDS = frozenset()

# Tier-B: keyword-only patterns have no regex of their own — their hits are
# hints that feed notes, never verdicts.
KEYWORD_ONLY_IDS = frozenset(p["id"] for p in PATTERNS if not p.get("regex"))

# Corroboration requires at least this severity from each finding.
_CORROBORATING_SEVERITIES = ("high", "critical")

BOUNDARY_LABEL = "Agent-context decision, not repo reputation."


def is_note_only(finding: dict) -> bool:
    """True if this finding can only ever feed notes (Tier-B / defused)."""
    if finding["id"] in KEYWORD_ONLY_IDS:
        return True
    if finding["severity"] not in _CORROBORATING_SEVERITIES:
        return True
    return False


# ── Display surface (repo scan) ──────────────────────────────────────────────

def rollup_repo(files: list, tier_s: frozenset = None) -> dict:
    """Grade a repo scan on the ladder. `files` = [{"name", "findings"}, ...]."""
    if tier_s is None:
        tier_s = TIER_S_SIGNATURE_IDS

    overall = "clean"
    notes = []
    review_files = []
    signature_hits = []

    for f in files:
        name = f.get("name", "?")
        findings = f.get("findings", [])
        for finding in findings:
            entry = {
                "file": name,
                "id": finding["id"],
                "severity": finding["severity"],
                "category": finding.get("category", ""),
                "matched_text": finding.get("matched_text", ""),
            }
            if finding["id"] in tier_s:
                signature_hits.append(entry)
            else:
                notes.append(entry)

        # Corroboration: 2+ DISTINCT pattern ids on 2+ DISTINCT text spans,
        # SAME category, each high+ regex-confirmed, in THIS file. Distinct
        # categories scattered through prose (the mempalace shape) never
        # corroborate, and two patterns matching the SAME span (the claude-seo
        # shape) are one piece of evidence, not two independent witnesses.
        by_category = {}
        for finding in findings:
            if is_note_only(finding) or finding["id"] in tier_s:
                continue
            ids, spans = by_category.setdefault(
                finding["category"], (set(), set()))
            ids.add(finding["id"])
            spans.add(finding.get("matched_text", ""))
        corroborated = [cat for cat, (ids, spans) in by_category.items()
                        if len(ids) >= 2 and len(spans) >= 2]
        if corroborated:
            review_files.append({"file": name, "categories": corroborated})

    if signature_hits:
        overall = "known_attack"
    elif review_files:
        overall = "review_before_agent_ingestion"
    elif notes:
        overall = "clean_notes"

    return {
        "overall": overall,
        "boundary": BOUNDARY_LABEL,
        "notes": notes,
        "review": review_files,
        "signature_hits": signature_hits,
        "files_scanned": len(files),
    }
