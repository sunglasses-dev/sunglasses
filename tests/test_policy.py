"""
test_policy.py — THE POLICY LAYER (verdict redesign, Jul 17 2026).

Born from the Patient Zero interview + Fugu's architecture doc + the Anthropic
comparison: the engine REPORTS findings; a single policy layer decides the
action per surface and mode; BLOCK is only shown where we actually block model
input.

Two surfaces, two functions:

  decide_enforce(findings)  — enforcement surfaces (paste/message/runtime/CLI).
                              Byte-identical to the legacy worst-severity map.
                              A pasted prompt is a model-input boundary: BLOCK
                              there is honest and stays.

  rollup_repo(files)        — display/diagnostic surface (repo scan). A repo is
                              not a prompt. Ladder:
                                clean                          (no findings)
                                clean_notes                    (uncorroborated /
                                                                keyword-only /
                                                                negation-context)
                                review_before_agent_ingestion (2+ independent
                                                                same-category
                                                                high+ findings
                                                                in one file)
                                known_attack                   (Tier-S curated
                                                                signature ONLY)

The mempalace invariant (the bug that forced this layer): three findings in
three DIFFERENT categories scattered through README prose are noise, not an
attack — a 57k-star repo must come back clean_notes, never red. A real
injection payload trips multiple patterns of the SAME category on the same
text: that corroboration is what earns REVIEW.
"""

import pytest

from sunglasses.patterns import PATTERNS
from sunglasses.policy import (
    SEVERITY_TO_DECISION,
    TIER_S_SIGNATURE_IDS,
    decide_enforce,
    is_note_only,
    rollup_repo,
)


def _finding(id="GLS-TEST-001", severity="high", category="prompt_injection",
             **extra):
    f = {"id": id, "name": "test", "severity": severity, "category": category,
         "matched_text": "x"}
    f.update(extra)
    return f


KEYWORD_ONLY_ID = next(p["id"] for p in PATTERNS if not p.get("regex"))
KEYWORD_ONLY_ID_2 = [p["id"] for p in PATTERNS if not p.get("regex")][1]
KEYWORD_ONLY_CAT = next(
    p["category"] for p in PATTERNS if p["id"] == KEYWORD_ONLY_ID)
REGEX_CONFIRMED_ID = next(p["id"] for p in PATTERNS if p.get("regex"))


# ── Enforcement surface: legacy behavior, byte-identical ────────────────────

class TestDecideEnforce:
    def test_no_findings_allows(self):
        assert decide_enforce([]) == "allow"

    @pytest.mark.parametrize("severity,expected", [
        ("critical", "block"),
        ("high", "block"),
        ("medium", "quarantine"),
        ("low", "allow_redacted"),
        ("review", "allow_redacted"),
    ])
    def test_severity_map_unchanged(self, severity, expected):
        assert decide_enforce([_finding(severity=severity)]) == expected

    def test_worst_severity_wins(self):
        findings = [_finding(severity="low"), _finding(severity="critical"),
                    _finding(severity="medium")]
        assert decide_enforce(findings) == "block"

    def test_engine_map_is_policy_map(self):
        # Single source of truth: the engine must use THIS map, not a copy.
        from sunglasses.engine import SunglassesEngine
        assert SunglassesEngine.SEVERITY_TO_DECISION is SEVERITY_TO_DECISION


# ── Repo surface: the ladder ────────────────────────────────────────────────

class TestRollupRepo:
    def test_no_findings_is_clean(self):
        result = rollup_repo([{"name": "README.md", "findings": []}])
        assert result["overall"] == "clean"

    def test_single_finding_is_notes_not_red(self):
        files = [{"name": "README.md", "findings": [_finding(severity="high")]}]
        assert rollup_repo(files)["overall"] == "clean_notes"

    def test_mempalace_invariant_distinct_categories_stay_notes(self):
        # The exact shape that painted mempalace (57k★) red on v0.3.3:
        # three findings, three DIFFERENT categories, prose context.
        files = [{"name": "README.md", "findings": [
            _finding(id="GLS-PI-002", severity="high",
                     category="prompt_injection"),
            _finding(id="GLS-PE-004", severity="medium",
                     category="privilege_escalation"),
            _finding(id="GLS-SCHEMA-LEAK-215", severity="critical",
                     category="prompt_leak"),
        ]}]
        assert rollup_repo(files)["overall"] == "clean_notes"

    def test_same_category_corroboration_earns_review(self):
        # A real payload trips multiple patterns of the SAME category.
        files = [{"name": "README.md", "findings": [
            _finding(id="GLS-PI-101", severity="high",
                     category="prompt_injection"),
            _finding(id="GLS-PI-202", severity="critical",
                     category="prompt_injection"),
        ]}]
        assert rollup_repo(files)["overall"] == "review_before_agent_ingestion"

    def test_corroboration_must_be_same_file(self):
        files = [
            {"name": "a.md", "findings": [
                _finding(id="GLS-PI-101", severity="high")]},
            {"name": "b.md", "findings": [
                _finding(id="GLS-PI-202", severity="high")]},
        ]
        assert rollup_repo(files)["overall"] == "clean_notes"

    def test_duplicate_pattern_id_does_not_corroborate_itself(self):
        files = [{"name": "README.md", "findings": [
            _finding(id="GLS-PI-101", severity="high"),
            _finding(id="GLS-PI-101", severity="high"),
        ]}]
        assert rollup_repo(files)["overall"] == "clean_notes"

    def test_medium_findings_do_not_corroborate(self):
        files = [{"name": "README.md", "findings": [
            _finding(id="GLS-PI-101", severity="medium"),
            _finding(id="GLS-PI-202", severity="medium"),
        ]}]
        assert rollup_repo(files)["overall"] == "clean_notes"

    def test_keyword_only_patterns_never_corroborate(self):
        # Tier-B: keyword-only hits are hints — notes at most.
        files = [{"name": "README.md", "findings": [
            _finding(id=KEYWORD_ONLY_ID, severity="high",
                     category=KEYWORD_ONLY_CAT),
            _finding(id=KEYWORD_ONLY_ID_2, severity="high",
                     category=KEYWORD_ONLY_CAT),
        ]}]
        assert rollup_repo(files)["overall"] == "clean_notes"

    def test_negation_context_never_corroborates(self):
        # Negation-downgraded findings carry severity="review".
        files = [{"name": "README.md", "findings": [
            _finding(id="GLS-PI-101", severity="review",
                     negation_context=True, original_severity="high"),
            _finding(id="GLS-PI-202", severity="review",
                     negation_context=True, original_severity="critical"),
        ]}]
        assert rollup_repo(files)["overall"] == "clean_notes"

    def test_tier_s_signature_is_known_attack(self):
        files = [{"name": "README.md", "findings": [
            _finding(id="GLS-SIG-EXFIL-001", severity="critical")]}]
        result = rollup_repo(files, tier_s=frozenset({"GLS-SIG-EXFIL-001"}))
        assert result["overall"] == "known_attack"

    def test_tier_s_ships_empty_until_curated(self):
        # Red is structurally impossible until a human curates signatures in.
        assert TIER_S_SIGNATURE_IDS == frozenset()

    def test_boundary_label_always_present(self):
        result = rollup_repo([{"name": "README.md", "findings": []}])
        assert result["boundary"] == \
            "Agent-context decision, not repo reputation."

    def test_notes_carry_receipts(self):
        files = [{"name": "README.md", "findings": [
            _finding(id="GLS-PI-002", severity="high")]}]
        result = rollup_repo(files)
        assert result["notes"], "notes list must not be empty"
        note = result["notes"][0]
        assert note["file"] == "README.md"
        assert note["id"] == "GLS-PI-002"


# ── Tier helper ──────────────────────────────────────────────────────────────

class TestIsNoteOnly:
    def test_keyword_only_pattern_is_note_only(self):
        assert is_note_only(_finding(id=KEYWORD_ONLY_ID, severity="high"))

    def test_negation_review_is_note_only(self):
        assert is_note_only(_finding(severity="review", negation_context=True))

    def test_regex_confirmed_high_is_not_note_only(self):
        assert not is_note_only(
            _finding(id=REGEX_CONFIRMED_ID, severity="high"))
