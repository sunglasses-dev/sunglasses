"""What a nightly report is allowed to say, and in which words.

ASTRA's design verdict of 2026-09-14 (GAUNTLET_PAGE_DESIGN_REVIEW, E2) rejected
the first shape for overloading `null`, `false` and `0` with three different
meanings. In that shape a count of zero could mean measured-zero, refused, or
never-run, and a reader could not tell which, so the page could publish a
refusal as an achievement without anyone lying.

So every panel here carries an explicit STATE, and the number beside it is only
readable when the state says a number was measured. `not_computed` is not
`0`. `unavailable` is not `false`. A missing observation is not a pass.

Two vocabularies are closed on purpose:

  STATES        what kind of thing the panel is showing
  REASON_CODES  why, when it is not a plain measurement

N1/N2 in the verdict: free prose has no automatic falsifier, and the sample's
fixed explanation string would have stayed on the page unchanged while the
boolean it explained flipped. So the page never renders an author's sentence
about a state. It renders a template selected BY the state and filled from
validated counts, and a reason code that a test can assert on.
"""
from __future__ import annotations

SCHEMA_VERSION = 2

# --- how a panel can be ------------------------------------------------------
# One primary state per panel. These are exhaustive and mutually exclusive: the
# validator refuses a panel carrying two, or one outside this set.
STATES = frozenset({
    "measured",       # this run observed it, and the evidence is bound
    "historical",     # a dated earlier examination, carried with its date
    "not_computed",   # refused: an input was unknown. NOT zero, NOT false
    "not_applicable",  # the question does not arise (e.g. no blocked variants)
    "unavailable",    # insufficient evidence. NOT a product failure
    "invalid",        # the artifact contradicts itself or its manifest
    "not_run",        # planned and never executed. NOT a pass, NOT a failure
})

# States in which a numeric value may be rendered at all. Anything else renders
# its state word, never a digit, because a digit is read as a measurement.
NUMERIC_STATES = frozenset({"measured", "historical"})

# --- why, when it is not a plain measurement ---------------------------------
# A closed set so a test can assert the code and a renderer can select a
# sentence. Adding one is an edit here, in the same commit as its template.
REASON_CODES = {
    # ceiling
    "CEILING_UNCLASSIFIED_OPS":
        "at least one operation has no reviewed capability classification",
    "CEILING_ADAPTER_ONLY_MEMBER":
        "at least one blocked variant needs no real-route capability",
    "CEILING_ALL_BLOCKED_NEED_ROUTE":
        "every blocked variant names at least one real-route capability",
    "CEILING_NO_BLOCKED_VARIANTS":
        "no variant is blocked, so the question does not arise",
    # planning / execution
    "PLAN_INVALID_SCHEDULE": "a schedule is not the shape the contract froze",
    "PLAN_PLANNER_ERROR": "the planner raised where it should have refused",
    "EXEC_NOT_RUN": "planned and not executed in this run",
    "EXEC_OBSERVER_ABSENT": "a required independent observation is missing",
    "EXEC_CONTRADICTED": "an independent observation contradicts the candidate",
    # evidence / identity
    "EVIDENCE_UNBOUND": "no evidence reference for a claim-bearing field",
    "IDENTITY_UNPINNED": "an identity is a name or an abbreviation, not a full digest",
    "SOURCE_UNREACHABLE": "a reachability check failed; availability is unknown",
    "ARCHIVE_MISSING": "the archived evidence could not be retrieved or verified",
    # run
    "RUN_REFUSED": "the run refused rather than publish an unknown as a number",
    "RUN_FAILED": "the run did not finish",
    "RUN_INCOMPLETE": "the run started and did not reach a terminal state",
}

# --- partitions --------------------------------------------------------------
# E2: rows, variants and physical executions are different units and never
# share a denominator. Each partition is exhaustive: the validator refuses a
# report whose parts do not sum to its declared total.

# A required contract row, after examination.
ROW_STATES = ("conformant", "non_conformant", "invalid", "unobserved", "not_run")

# Planning membership of a corpus variant. Disjoint from execution outcome:
# a variant can be drivable and still never run, and E2 forbids counting a
# planned-but-unrun variant as passed.
PLAN_STATES = ("drivable", "blocked", "invalid")

# What physically happened to a variant this run.
EXEC_STATES = ("passed", "failed", "refused", "errored", "not_run")

# Ceiling is four-valued. `false` is informative, not a product failure, and
# `not_computed` is not `false`.
CEILING_STATES = ("true", "false", "not_computed", "not_applicable")

# Origin reachability is three-valued: a failed network check means unknown,
# never "gone". E8.
REACHABILITY_STATES = ("reachable", "unreachable", "unknown")

# What kind of thing was actually executed. E7: a stand-in is not a candidate,
# a candidate is not a merged route, and a merged route is not a release.
IMPLEMENTATION_KINDS = ("harness_stand_in", "product_candidate",
                        "merged_product_source", "released_artifact")

# The unit the ledger counts. E9: not dollars, not provider requests.
LEDGER_UNIT = "charged driver invocations"

# E6. The policy lives in the committed artifact, not in the renderer, so a
# reader can check the number the page enforced against the number it claims.
DEFAULT_FRESHNESS_HOURS = 36


def numeric_readable(panel: dict) -> bool:
    """True when this panel's digits may be shown.

    The single place the rule lives. A panel in `not_computed` that happens to
    carry a stale integer from an earlier attempt renders its state, not the
    integer.
    """
    return panel.get("state") in NUMERIC_STATES
