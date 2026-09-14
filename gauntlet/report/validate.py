"""Read the report as a hostile reader would, and refuse it if it cannot stand.

E3's separation, which is the point of this file existing at all: checking that
the HTML matches the JSON proves TRANSCRIPTION and nothing else. A report whose
summary says 30 drivable while its own id list holds 27 is perfectly
transcribable, and a page built from it would be perfectly wrong. So the
aggregates are RECOMPUTED here from the underlying manifests, and the report's
own summary is treated as a claim to be checked rather than a source to be read.

Two separate checks, and a mutation that defeats one must not defeat the other:

  validate_report   recomputes every total from the ids beneath it
  check_transcription  compares the rendered page against the validated JSON

Change a number in the JSON alone and transcription catches it. Change the JSON
and the HTML together and recomputation catches it. Changing the underlying
rows changes the measurement, which is the only honest way to move a number.
"""
from __future__ import annotations

import dataclasses
import re

import schema


@dataclasses.dataclass(frozen=True)
class Finding:
    code: str
    path: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code} at {self.path}: {self.detail}"


FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


def _state_of(panel, path, findings) -> str | None:
    if not isinstance(panel, dict):
        findings.append(Finding("PANEL_NOT_AN_OBJECT", path, f"got {type(panel).__name__}"))
        return None
    state = panel.get("state")
    if state not in schema.STATES:
        findings.append(Finding(
            "UNKNOWN_STATE", path,
            f"{state!r} is not one of {sorted(schema.STATES)}. An unrecognised "
            "state is not a third kind of answer, it is an invalid artifact."))
        return None
    return state


def validate_report(report: dict) -> list[Finding]:
    """Everything wrong with this artifact. Empty means publishable."""
    findings: list[Finding] = []

    if report.get("schema") != schema.SCHEMA_VERSION:
        findings.append(Finding(
            "SCHEMA_UNKNOWN", "schema",
            f"{report.get('schema')!r} is not version {schema.SCHEMA_VERSION}. "
            "A reader cannot know which fields mean what."))
        return findings

    run = report.get("run") or {}
    for key in ("id", "attempt", "started_at", "finished_at", "outcome", "exit_code"):
        if key not in run:
            findings.append(Finding("RUN_INCOMPLETE_IDENTITY", f"run.{key}", "absent"))
    if run.get("outcome") not in ("complete", "refused", "failed", "incomplete"):
        findings.append(Finding("RUN_OUTCOME_UNKNOWN", "run.outcome", repr(run.get("outcome"))))
    # E5: a refusal that exits zero is the failure mode this whole file guards.
    if run.get("outcome") in ("refused", "failed") and run.get("exit_code") == 0:
        findings.append(Finding(
            "REFUSAL_EXITED_ZERO", "run.exit_code",
            "the run refused or failed and reported success. A refusal that "
            "exits zero is indistinguishable from a clean run to everything "
            "downstream of it."))
    if run.get("outcome") == "complete" and run.get("exit_code") not in (0, None):
        findings.append(Finding("COMPLETE_EXITED_NONZERO", "run.exit_code",
                                f"outcome complete with exit {run.get('exit_code')}"))

    fresh = report.get("freshness") or {}
    if not isinstance(fresh.get("policy_hours"), (int, float)):
        findings.append(Finding(
            "FRESHNESS_POLICY_MISSING", "freshness.policy_hours",
            "the policy must be in the committed artifact, so a reader can "
            "check the limit the page enforced against the limit it claims."))
    if not fresh.get("measured_at"):
        findings.append(Finding("FRESHNESS_NO_MEASURED_AT", "freshness.measured_at",
                                "generation time cannot stand in for measurement time"))

    findings += _validate_coverage(report.get("coverage"))
    findings += _validate_routes(report.get("routes"))

    findings += _validate_harness(report.get("harness"))

    for name in ("harness", "ledger"):
        panel = report.get(name)
        state = _state_of(panel, name, findings)
        # `_state_of` already recorded a finding for anything that is not an
        # object, and reading `.get` off it here would raise instead of refuse.
        # A validator that raises does not report; it takes the build down with
        # a stack trace, and a pipeline that swallows exceptions reads the
        # silence as nothing wrong.
        if not isinstance(panel, dict):
            continue
        if state in ("unavailable", "invalid", "not_computed") and not panel.get("reason_code"):
            findings.append(Finding("REASON_CODE_MISSING", name,
                                    f"state {state} with no reason code"))
        if panel.get("reason_code") and panel["reason_code"] not in schema.REASON_CODES:
            findings.append(Finding(
                "REASON_CODE_UNKNOWN", f"{name}.reason_code",
                f"{panel['reason_code']!r} is not in the closed set. Free prose "
                "in this slot has no falsifier, which is why the set is closed."))
    return findings


def _validate_harness(harness) -> list[Finding]:
    """FIT and mutation scores, and the ways a green one can be false.

    A mutation score is a statement about the tests. It only means anything if
    every mutant was actually APPLIED and the baseline was green before it: a
    mutant that never ran, errored, or ran against an already-red suite is
    invalid, and invalid is never a rejection. Counting those as kills is how a
    cached bytecode file produced a kill count for the previous mutant.
    """
    findings: list[Finding] = []
    if not isinstance(harness, dict):
        return findings
    state = harness.get("state")
    if state not in schema.NUMERIC_STATES:
        return findings

    # E1: a numeric FIT panel is an IMPORT. It cannot be minted by the run.
    record = harness.get("record")
    if not isinstance(record, dict) or not harness.get("record_digest"):
        findings.append(Finding(
            "FIT_NOT_IMPORTED", "harness.record",
            "a numeric FIT panel with no examiner-authored record and digest "
            "beneath it. A run asserting FIT from its own passing suite is the "
            "defendant writing the verdict."))
        return findings

    met, of = record.get("met"), record.get("of")
    if isinstance(met, int) and isinstance(of, int) and met > of:
        findings.append(Finding("AGGREGATE_MISMATCH", "harness.record.met",
                                f"{met} met of {of} required"))
    if not str(record.get("exam_head", "")).strip() or not FULL_SHA.match(
            str(record.get("exam_head", ""))):
        findings.append(Finding(
            "IDENTITY_UNPINNED", "harness.record.exam_head",
            f"{record.get('exam_head')!r} is not a full commit. An "
            "abbreviation cannot bind a historical examination."))
    if not record.get("examined_at"):
        findings.append(Finding("FIT_UNDATED", "harness.record.examined_at",
                                "a historical finding with no date reads as current"))

    mutants = record.get("mutants")
    if isinstance(mutants, dict):
        rejected = mutants.get("rejected")
        total = mutants.get("total")
        statuses = mutants.get("statuses") or {}
        countable = statuses.get("rejected", rejected)
        invalid_kinds = sum(statuses.get(k, 0) for k in
                            ("survived", "errored", "not_applied", "red_baseline"))
        if isinstance(rejected, int) and isinstance(total, int) and rejected > total:
            findings.append(Finding("AGGREGATE_MISMATCH", "harness.record.mutants",
                                    f"{rejected} rejected of {total}"))
        if statuses and isinstance(total, int) and sum(statuses.values()) != total:
            findings.append(Finding(
                "AGGREGATE_MISMATCH", "harness.record.mutants.statuses",
                f"statuses sum to {sum(statuses.values())} against {total}"))
        if statuses and countable != rejected:
            findings.append(Finding(
                "MUTATION_SUMMARY_CONTRADICTED", "harness.record.mutants.rejected",
                f"the summary claims {rejected} rejected while the per-mutant "
                f"statuses record {countable}."))
        # COMPLETENESS, not just arithmetic. The first version of this fired
        # only when the score was perfect, so a run with three errored mutants
        # and a score of 119 of 122 passed silently. The arithmetic was fine;
        # the RUN was not. A mutant that survived, errored, never applied or
        # ran from an already red baseline means this examination is incomplete,
        # and an incomplete examination may not publish a clean score. It may
        # publish an explicitly incomplete one, which is a different claim.
        if invalid_kinds and record.get("completeness") != "incomplete":
            findings.append(Finding(
                "MUTATION_SUMMARY_CONTRADICTED", "harness.record.mutants",
                f"{invalid_kinds} mutants survived, errored, never applied or "
                "ran from a red baseline, and the record does not declare "
                "itself incomplete. An invalid execution is never a rejection, "
                "and a kill count taken over a suite that was not green is not "
                "a kill count."))
    return findings


def _validate_coverage(coverage) -> list[Finding]:
    findings: list[Finding] = []
    state = _state_of(coverage, "coverage", findings)
    if state is None or state == "unavailable":
        return findings

    plan = coverage.get("plan_partition") or {}
    drivable_ids = coverage.get("drivable_ids") or []
    blocked_ids = coverage.get("blocked_ids") or []
    invalid_detail = coverage.get("invalid_detail") or {}

    # RECOMPUTED, not read. This is the check a coordinated JSON+HTML edit
    # cannot survive, because it never looks at the summary to find the answer.
    recomputed = {
        "drivable": len(set(drivable_ids)),
        "blocked": len(set(blocked_ids)),
        "invalid": len(set(invalid_detail)),
    }
    for key, value in recomputed.items():
        if plan.get(key) != value:
            findings.append(Finding(
                "AGGREGATE_MISMATCH", f"coverage.plan_partition.{key}",
                f"the report says {plan.get(key)}; recomputing from the ids "
                f"beneath it gives {value}."))

    overlap = set(drivable_ids) & set(blocked_ids)
    if overlap:
        findings.append(Finding(
            "MEMBERSHIP_OVERLAP", "coverage",
            f"{sorted(overlap)} are counted as both drivable and blocked. One "
            "primary state per variant, or a reader can pick the kinder total."))
    for name, ids in (("drivable_ids", drivable_ids), ("blocked_ids", blocked_ids)):
        if len(ids) != len(set(ids)):
            findings.append(Finding("DUPLICATE_IDS", f"coverage.{name}",
                                    "a duplicated id inflates its own partition"))

    total = coverage.get("total")
    if total != sum(recomputed.values()):
        findings.append(Finding(
            "TOTAL_MISMATCH", "coverage.total",
            f"{total} is not the sum of the recomputed partition "
            f"{sum(recomputed.values())}. A missing variant cannot shrink a "
            "denominator: that is how a dropped failure becomes a better score."))

    execution = coverage.get("execution_partition") or {}
    missing_exec = [k for k in schema.EXEC_STATES if k not in execution]
    if missing_exec:
        findings.append(Finding("EXEC_PARTITION_INCOMPLETE",
                                "coverage.execution_partition", f"absent: {missing_exec}"))
    elif sum(execution.values()) != total:
        findings.append(Finding(
            "EXEC_PARTITION_MISMATCH", "coverage.execution_partition",
            f"sums to {sum(execution.values())} against a total of {total}"))
    # E2: planning is not execution. A planned-but-unrun variant is never passed.
    if execution.get("passed", 0) > (plan.get("drivable") or 0):
        findings.append(Finding(
            "EXEC_EXCEEDS_PLAN", "coverage.execution_partition.passed",
            "more variants passed than were ever drivable"))

    findings += _validate_ceiling(coverage.get("ceiling"), blocked_ids)
    return findings


def _validate_ceiling(ceiling, blocked_ids) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(ceiling, dict):
        findings.append(Finding("CEILING_ABSENT", "coverage.ceiling", "no ceiling panel"))
        return findings

    state = ceiling.get("state")
    if state not in schema.CEILING_STATES:
        findings.append(Finding("CEILING_STATE_UNKNOWN", "coverage.ceiling.state",
                                f"{state!r} not in {list(schema.CEILING_STATES)}"))
        return findings
    if ceiling.get("reason_code") not in schema.REASON_CODES:
        findings.append(Finding("REASON_CODE_UNKNOWN", "coverage.ceiling.reason_code",
                                repr(ceiling.get("reason_code"))))

    route = ceiling.get("blocked_needing_route")
    alone = ceiling.get("blocked_by_adapter_work_alone")

    if state in ("not_computed", "not_applicable"):
        # THE ZERO TRAP. A refusal empties the lists, and a subtotal of zero
        # then reads as "nothing is blocking", which is the opposite of what
        # happened. Null is the only honest value here.
        for name, value in (("blocked_needing_route", route),
                            ("blocked_by_adapter_work_alone", alone)):
            if value is not None:
                findings.append(Finding(
                    "REFUSAL_PUBLISHED_A_NUMBER", f"coverage.ceiling.{name}",
                    f"state is {state} and this reads {value!r}. A count that "
                    "exists only because a refusal emptied a list is not a "
                    "measurement of zero."))
        if state == "not_computed":
            count = ceiling.get("unclassified_count")
            listed = ceiling.get("unclassified") or {}
            if not count:
                findings.append(Finding(
                    "REFUSAL_WITHOUT_CAUSE", "coverage.ceiling.unclassified_count",
                    "a refusal must name how many distinct things it could not "
                    "classify, or it cannot be checked or fixed"))
            elif count != len(listed):
                findings.append(Finding(
                    "AGGREGATE_MISMATCH", "coverage.ceiling.unclassified_count",
                    f"says {count}, lists {len(listed)}"))
        if state == "not_applicable" and blocked_ids:
            findings.append(Finding(
                "CEILING_NOT_APPLICABLE_WITH_BLOCKERS", "coverage.ceiling.state",
                f"{len(blocked_ids)} variants are blocked, so the question "
                "does arise"))
        return findings

    # A computed ceiling must account for every blocked variant exactly once.
    if not isinstance(route, int) or not isinstance(alone, int):
        findings.append(Finding("CEILING_SUBTOTALS_MISSING", "coverage.ceiling",
                                "a computed ceiling with no subtotals beneath it"))
        return findings
    if route + alone != len(set(blocked_ids)):
        findings.append(Finding(
            "AGGREGATE_MISMATCH", "coverage.ceiling",
            f"{route} + {alone} does not account for {len(set(blocked_ids))} "
            "blocked variants"))
    if state == "true" and alone != 0:
        findings.append(Finding(
            "CEILING_CONTRADICTED", "coverage.ceiling.state",
            f"claims a ceiling while {alone} variants need no route capability"))
    if state == "false" and alone == 0:
        findings.append(Finding("CEILING_CONTRADICTED", "coverage.ceiling.state",
                                "claims no ceiling with no adapter-only variant"))
    return findings


def _validate_routes(routes) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(routes, list):
        findings.append(Finding("ROUTES_ABSENT", "routes", "no routes array"))
        return findings
    seen = set()
    for index, route in enumerate(routes):
        path = f"routes[{index}]"
        name = route.get("name")
        if name in seen:
            findings.append(Finding("DUPLICATE_ROUTE", path, f"{name!r} twice"))
        seen.add(name)
        kind = route.get("implementation_kind")
        if kind not in schema.IMPLEMENTATION_KINDS:
            findings.append(Finding(
                "IMPLEMENTATION_KIND_UNKNOWN", f"{path}.implementation_kind",
                f"{kind!r}. A stand-in, a candidate, a merged source and a "
                "released artifact are four different things and the page may "
                "not blur them."))
        head = route.get("head")
        if head is not None and not FULL_SHA.match(str(head)):
            findings.append(Finding(
                "IDENTITY_UNPINNED", f"{path}.head",
                f"{head!r} is not a full 40 character commit. A branch name "
                "moves and an abbreviation is not an identity."))
        if route.get("head_reachable_on_origin") not in schema.REACHABILITY_STATES:
            findings.append(Finding(
                "REACHABILITY_STATE_UNKNOWN", f"{path}.head_reachable_on_origin",
                "reachability is reachable, unreachable or unknown; a failed "
                "network check means unknown, never gone"))
        rows = route.get("rows") or {}
        state = _state_of(rows, f"{path}.rows", findings)
        if state in schema.NUMERIC_STATES:
            findings += _validate_rows(rows, f"{path}.rows", route)
        # E7: a stand-in's planning numbers may never be relabelled as route
        # conformance. The kind and the claim are checked together.
        if kind == "harness_stand_in" and state in schema.NUMERIC_STATES:
            findings.append(Finding(
                "STANDIN_CLAIMED_AS_ROUTE", f"{path}.rows",
                "a harness stand-in cannot carry route conformance rows. Those "
                "would be a verdict about the instrument wearing the label of "
                "a verdict about the product."))
    return findings


def _validate_rows(rows, path, route) -> list[Finding]:
    """Conformance is per row, and a row earns it only with its evidence.

    Two ways a green row is false, both of them seen this week: an observation
    that was never made counts as a pass, and a product's own receipt is read
    as the outside witness of its own behaviour.
    """
    findings: list[Finding] = []
    if route.get("head") is None:
        findings.append(Finding(
            "ROWS_WITHOUT_HEAD", path,
            "row results with no executed head beneath them. A score with no "
            "identity attaches to whatever the reader assumes."))
    results = rows.get("row_results")
    if not isinstance(results, dict) or not results:
        findings.append(Finding("ROWS_WITHOUT_MANIFEST", path,
                                "a numeric rows panel with no per-row results"))
        return findings

    counts = {state: 0 for state in schema.ROW_STATES}
    for row_id, result in results.items():
        state = result.get("state")
        if state not in schema.ROW_STATES:
            findings.append(Finding("ROW_STATE_UNKNOWN", f"{path}.{row_id}",
                                    f"{state!r} not in {list(schema.ROW_STATES)}"))
            continue
        counts[state] += 1
        if state != "conformant":
            continue
        if not result.get("evidence"):
            findings.append(Finding(
                "CONFORMANT_WITHOUT_EVIDENCE", f"{path}.{row_id}",
                "a row cannot be conformant with no evidence reference. An "
                "observation that was never made is unobserved, not a pass."))
        if result.get("contradicted_by"):
            findings.append(Finding(
                "CONFORMANT_CONTRADICTED", f"{path}.{row_id}",
                f"an independent observation ({result['contradicted_by']}) "
                "contradicts this row and it is still counted conformant"))
        if result.get("observer_state") in ("absent", "disconnected"):
            findings.append(Finding(
                "CONFORMANT_WITHOUT_OBSERVER", f"{path}.{row_id}",
                "the independent observer was absent or disconnected, so this "
                "row is unobserved. Absence of observation is not conformance."))
        if result.get("scope") == "partial":
            findings.append(Finding(
                "PARTIAL_ROW_COUNTED_FULL", f"{path}.{row_id}",
                "a partial sub-obligation counted as a full conformant row"))
    declared = rows.get("counts")
    if isinstance(declared, dict):
        for state, value in declared.items():
            if counts.get(state) != value:
                findings.append(Finding(
                    "AGGREGATE_MISMATCH", f"{path}.counts.{state}",
                    f"declared {value}, recomputed {counts.get(state)}"))
    total = rows.get("total")
    if isinstance(total, int) and total != sum(counts.values()):
        findings.append(Finding(
            "TOTAL_MISMATCH", f"{path}.total",
            f"{total} against {sum(counts.values())} rows present. A missing "
            "row cannot shrink the denominator."))
    return findings


BOUND = re.compile(r'data-bound="([^"]+)"[^>]*>([^<]*)<')


def resolve(report: dict, path: str):
    """Follow a dotted path with [index] segments into the report."""
    node = report
    for part in path.split("."):
        if part.endswith("]") and "[" in part:
            name, index = part[:-1].split("[")
            node = node[name][int(index)]
        else:
            node = node[part]
    return node


def check_transcription(html: str, report: dict) -> list[Finding]:
    """Every rendered figure equals the validated artifact it cites.

    This is the weaker of the two checks and is labelled as such, because a
    coordinated edit to both files passes it. It exists to catch the renderer,
    not the author.
    """
    findings: list[Finding] = []
    seen = 0
    for path, rendered in BOUND.findall(html):
        seen += 1
        try:
            value = resolve(report, path)
        except (KeyError, IndexError, TypeError, ValueError):
            findings.append(Finding("BOUND_PATH_MISSING", path,
                                    "the page cites a field the artifact lacks"))
            continue
        if str(value) != rendered.strip():
            findings.append(Finding(
                "TRANSCRIPTION_MISMATCH", path,
                f"the page shows {rendered.strip()!r}; the artifact says {value!r}"))
    if not seen:
        findings.append(Finding(
            "NOTHING_BOUND", "html",
            "no rendered figure cites an artifact field. An unbound page is a "
            "page of hand-typed numbers, which is the defect this exists for."))
    return findings
