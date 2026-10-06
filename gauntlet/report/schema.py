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
    "EXEC_NONE": "the ceiling is computed and no variant was executed, so there is nothing "
                 "behind the number",
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

# The ledger is two labelled lines and each line says its own scope. A bare
# zero beside the unit could mean "nothing was spent" or "nothing was counted",
# so the scope is a closed set and the words of each line are GENERATED from the
# line's fields by `ledger_line_text`, never typed. The validator recomputes the
# text and refuses a line whose words were written by hand.
LEDGER_SCOPES = ("cumulative_gate2", "no_live_calls_standin_run",
                 "live_driver_batch")


def ledger_line_text(line: dict) -> str:
    """The words of one ledger line, from its own fields and nothing else."""
    scope = line.get("scope")
    if scope == "cumulative_gate2":
        return (f"cumulative Gate 2, {line.get('charges')} of {line.get('cap')} "
                f"{LEDGER_UNIT}")
    if scope == "no_live_calls_standin_run":
        return f"this nightly, {line.get('charges')} live calls"
    if scope == "live_driver_batch":
        return (f"live driver batch, {line.get('charges')} of {line.get('cap')} "
                f"{LEDGER_UNIT}")
    return ""


# The driver's records (report/drive.py) and the run document around them.
EXEC_RECORD_SCHEMA = 1
EXEC_RUN_SCHEMA = 1

# ONE TABLE, FOR WHAT A DRIVER RECORD IS. The driver writes through it (`drive._finish` refuses to
# emit a record it rejects), the producer reads it on import, and the validator checks it. A field
# the table does not name is not a field, and a named one is null or of its type. A record of the
# wrong shape is not a record with a wrong value: it cannot be read at all, so it is refused whole
# and never counted around.
TEXT, FLAG, WHOLE, TEXTS, SCALAR = "text", "flag", "whole number", "list of text", "text or whole number"
_DIGEST_TEXT = TEXT
RECORD_FIELDS = {
    "record_schema": WHOLE, "variant_id": TEXT, "scenario_id": TEXT, "variant": TEXT,
    "route": TEXT, "implementation_kind": TEXT, "mode": TEXT, "control_route": TEXT,
    "started_at": TEXT, "finished_at": TEXT, "harness_head": TEXT, "delivered_digest": TEXT,
    "outcome": TEXT, "reason_code": TEXT, "cause": TEXT,
    "control": {"route": TEXT, "stimulus_delivered": FLAG, "refusal": TEXT,
                "payload_sent_by_client": FLAG, "payload_visible_at_client": FLAG,
                "declared_frames_reached_client": FLAG, "terminal_arrived": FLAG,
                "client_bound_wire_stable_sha256": TEXT, "execution_stable_sha256": TEXT},
    "expectation": {"source_sha256": TEXT, "policy_decision": TEXT,
                    "assert_original_payload_absent": FLAG, "bytes_outcome": TEXT,
                    "unreadable": FLAG},
    "assertions": {"held": TEXTS, "not_held": TEXTS, "no_subject": TEXTS,
                   "expect_payload_absent": FLAG, "payload_at_destination": FLAG,
                   "stimulus_origin": TEXT, "expect_original": FLAG,
                   "declared_frames_delivered_unchanged": FLAG},
    "graded_on": TEXTS, "steps": TEXTS, "primary_id": SCALAR, "terminal_expected": FLAG,
    "terminal_arrived": FLAG, "upstream_as_declared": FLAG, "mediator_disposition": TEXT,
    "client_bound_wire_stable_sha256": TEXT, "into_mediator_wire_stable_sha256": TEXT,
    "execution_stable_sha256": TEXT, "receipts_stable_sha256": TEXT,
    "volatile": {"bytes_to_client": WHOLE, "bytes_into_mediator": WHOLE,
                 "execution_sha256": TEXT, "receipts_sha256": TEXT},
    "stable_record_digest": TEXT,
}
RECORD_IDENTITY = ("variant_id", "outcome")        # never null: they say which variant, which result


def _has_shape(value, kind) -> bool:
    if value is None:
        return True
    if isinstance(kind, dict):
        return isinstance(value, dict)
    if kind == TEXT:
        return isinstance(value, str)
    if kind == FLAG:
        return isinstance(value, bool)
    if kind == WHOLE:
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == SCALAR:
        return isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool))
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _table_problem(node, table, where="") -> str | None:
    for key, value in node.items():
        if not isinstance(key, str) or key not in table:
            return f"{where}{key!r} is not a field of the record table"
        kind = table[key]
        if not _has_shape(value, kind):
            what = "an object" if isinstance(kind, dict) else kind
            return f"{where}{key} is not {what}"
        if isinstance(kind, dict) and isinstance(value, dict):
            inner = _table_problem(value, kind, f"{where}{key}.")
            if inner:
                return inner
    return None


def record_shape_problem(record) -> str | None:
    """Why this driver record cannot be read, or None. Never raises."""
    try:
        if not isinstance(record, dict):
            return "a record is not an object"
        for key in RECORD_IDENTITY:
            if not isinstance(record.get(key), str):
                return f"{key} is not text"
        return _table_problem(record, RECORD_FIELDS)
    except Exception as exc:                                # noqa: BLE001
        return f"the record could not be read, {type(exc).__name__}"


def canonical_digest(doc) -> str:
    """sha256 over a parsed document with sorted keys, so a digest does not depend on how a file
    happened to be indented. The producer writes it and the validator recomputes it."""
    import hashlib
    import json
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()


def executed_total(coverage) -> int:
    """passed + failed + refused + errored, and 0 for anything that does not say."""
    part = coverage.get("execution_partition") if isinstance(coverage, dict) else None
    if not isinstance(part, dict):
        return 0
    return sum(v for k, v in part.items()
               if k in ("passed", "failed", "refused", "errored")
               and isinstance(v, int) and not isinstance(v, bool))


def nothing_executed(coverage) -> bool:
    """V15. A measured coverage panel under which no variant has an executed outcome."""
    return (isinstance(coverage, dict) and coverage.get("state") == "measured"
            and executed_total(coverage) == 0)


def records_digest(records: list) -> str:
    """The digest that binds a run's records: sorted by variant id, serialised with sorted keys."""
    return canonical_digest(sorted(
        records, key=lambda r: str(r.get("variant_id", "")) if isinstance(r, dict) else ""))


# What the executed variants ran on, in the words the page must carry as data
# beside the route name and the implementation kind. It states the limit of the
# examiner's finding, which covers an earlier and smaller harness, and that the
# executor which drove these variants came after it and was not examined. It
# holds no measured number, so it can sit on a public page without becoming one.
STANDIN_SCOPE_SENTENCE = (
    "These variants ran on the harness stand in route, which is the test "
    "instrument and not the product. The examiner's FIT finding covers an "
    "earlier and smaller version of the harness, and the executor that ran "
    "these variants was written after it and has not been examined.")

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


# WHAT RENDER MAY READ. One table for every field the page is built from, and the page is built
# from the view this table cuts out of a report and from nothing else. The validator types each
# field here (`REPORT_FIELD_TYPE`), so a report that passes has a view render cannot trip on, and
# a field the table does not name cannot reach the page. A kind is text, a whole number or a number
# (a bool is none of them), OBJECT for a thing only its presence is read of, a table for an object,
# or a wrapped kind: `_opt` null or absent, `_nul` present but null allowed, `_list` of, `_map` of
# text keys to.
NUMBER, OBJECT = "number", "object"


def _opt(kind): return ("opt", kind)
def _nul(kind): return ("nul", kind)
def _list(kind): return ("list", kind)
def _map(kind): return ("map", kind)


_PANEL = {"state": _opt(TEXT), "reason_code": _opt(TEXT), "detail": _opt(TEXT)}
REPORT_READS = {
    "run": {"id": TEXT, "attempt": WHOLE, "finished_at": TEXT, "outcome": TEXT,
            "exit_code": WHOLE, "reason_code": _opt(TEXT)},
    "freshness": {"measured_at": TEXT, "policy_hours": NUMBER},
    "identities": {"corpus_digest": _nul(TEXT), "capability_map_revision": _nul(TEXT),
                   "capability_map_review_state": _nul(TEXT)},
    "harness": dict(_PANEL),
    "coverage": dict(_PANEL, plan_partition=_opt({"drivable": _opt(WHOLE)}), total=_opt(WHOLE),
                     execution_partition=_opt({"passed": _opt(WHOLE), "not_run": _opt(WHOLE)}),
                     ceiling=_opt({"state": _opt(TEXT), "unclassified_count": _opt(WHOLE),
                                   "blocked_needing_route": _opt(WHOLE),
                                   "blocked_by_adapter_work_alone": _opt(WHOLE),
                                   "unclassified": _opt(_map(TEXT))})),
    "routes": _opt(_list({
        "name": _opt(TEXT), "implementation_kind": _opt(TEXT), "head": _opt(TEXT),
        "head_reachable_on_origin": _opt(TEXT), "rows": _opt(dict(_PANEL)),
        "execution": _opt({"state": _opt(TEXT), "harness_head": _opt(TEXT),
                           "records_digest": _opt(TEXT), "counts": _opt(_map(WHOLE)),
                           "fit_scope": _opt(TEXT)})})),
    "ledger": dict(_PANEL, lines=_opt(_list({
        "scope": _opt(TEXT), "state": _opt(TEXT), "reason_code": _opt(TEXT),
        "text": _opt(TEXT), "updated_at": _opt(TEXT)}))),
    "execution_run": _opt(OBJECT),
}
# A panel whose digits may be shown is read for them, so these must be there when it is.
_READ_WHEN_NUMERIC = (("plan_partition", "drivable"), ("total",), ("execution_partition", "passed"),
                      ("execution_partition", "not_run"), ("ceiling",))


def _has_kind(value, kind) -> bool:
    if kind == TEXT:
        return isinstance(value, str)
    if kind == WHOLE:
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == NUMBER:
        return (isinstance(value, (int, float)) and not isinstance(value, bool)
                and value == value and value not in (float("inf"), float("-inf")))
    return isinstance(value, dict)                          # OBJECT


def _cut(value, kind, path, problems, present=True):
    """The part of `value` the table names, appending a (path, why) for every field that is not
    what the table says. Returns None for a field that is null or absent."""
    wrap = kind[0] if isinstance(kind, tuple) else None
    if wrap in ("opt", "nul"):
        if value is None:
            if wrap == "nul" and not present:
                problems.append((path, "absent. The page shows this field, so it must be named"))
            return None
        kind, wrap = kind[1], (kind[1][0] if isinstance(kind[1], tuple) else None)
    elif value is None:
        problems.append((path, "absent" if not present else "null, and this field is required"))
        return None
    if isinstance(kind, dict):
        if not isinstance(value, dict):
            problems.append((path, f"not an object, it is {type(value).__name__}"))
            return None
        out = {}
        for key, sub in kind.items():
            got = _cut(value.get(key), sub, f"{path}.{key}" if path else key, problems,
                       key in value)
            if got is not None:
                out[key] = got
        return out
    if wrap == "list":
        if not isinstance(value, list):
            problems.append((path, f"not a list, it is {type(value).__name__}"))
            return None
        return [_cut(item, kind[1], f"{path}[{index}]", problems) for index, item in enumerate(value)]
    if wrap == "map":
        if not isinstance(value, dict):
            problems.append((path, f"not an object, it is {type(value).__name__}"))
            return None
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                problems.append((path, f"a key that is not text, {key!r}"))
                continue
            out[key] = _cut(item, kind[1], f"{path}.{key}", problems)
        return out
    if not _has_kind(value, kind):
        problems.append((path, f"not {kind}, it is {type(value).__name__}"))
        return None
    return value


def render_view(report) -> tuple[dict, list[tuple[str, str]]]:
    """(view, problems). The view holds only fields `REPORT_READS` names. Never raises."""
    problems: list[tuple[str, str]] = []
    try:
        if not isinstance(report, dict):
            return {}, [("report", "not an object")]
        view = _cut(report, REPORT_READS, "", problems) or {}
        coverage = view.get("coverage")
        if isinstance(coverage, dict) and numeric_readable(coverage):
            for chain in _READ_WHEN_NUMERIC:
                node = coverage
                for key in chain:
                    node = node.get(key) if isinstance(node, dict) else None
                if node is None:
                    problems.append((".".join(("coverage",) + chain),
                                     "absent, and this panel is measured so the page shows it"))
        return view, problems
    except Exception as exc:                                # noqa: BLE001
        return {}, problems + [("report", f"could not be read, {type(exc).__name__}")]
