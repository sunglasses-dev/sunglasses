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
import datetime
import re
from html.parser import HTMLParser

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
    findings += _validate_execution(report)
    findings += _validate_ledger(report)

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


def _when(value) -> datetime.datetime | None:
    try:
        parsed = datetime.datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.timezone.utc)


def _is_count(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


# Keys that would make an execution record or the route's execution block read as route
# conformance. The stand in's rows stay unavailable, and nothing beside them may stand in for them.
ROUTE_ROW_KEYS = frozenset({"rows", "row_results", "route_rows", "conformance", "conformant"})


def _validate_execution(report) -> list[Finding]:
    """The driver's records, read as a hostile reader would, rule V1 to V14.

    The run document is embedded in the report so every count below is RECOMPUTED from the
    records and never read from a summary. A document that fails here is not a smaller number,
    it is an invalid artifact: the validator accepting a wrong `passed` is the page's only guard.
    """
    findings: list[Finding] = []
    coverage = report.get("coverage")
    run = report.get("execution_run")
    identities = report.get("identities") or {}
    measured_cov = isinstance(coverage, dict) and coverage.get("state") == "measured"
    declared = coverage.get("execution_state") if measured_cov else None
    valid_shape = (isinstance(run, dict) and isinstance(run.get("header"), dict)
                   and isinstance(run.get("records"), list))

    # V12. A measured execution state exists only with a run document beneath it, and a run
    # document exists only beneath a measured execution state. A zero `passed` presented as
    # measured, with nothing run, is the failure this guards.
    if declared == "measured" and not valid_shape:
        findings.append(Finding(
            "EXEC_STATE_UNBACKED", "coverage.execution_state",
            "the execution state is measured and no run document is beneath it"))
    if run is not None and (declared != "measured" or not valid_shape):
        findings.append(Finding(
            "EXEC_STATE_UNBACKED", "execution_run",
            "a run document is present and the execution state does not stand on it"))
    bound = declared == "measured" and valid_shape
    part = coverage.get("execution_partition") if measured_cov else None
    if declared == "not_run" and coverage.get("execution_reason_code") != "EXEC_NOT_RUN":
        findings.append(Finding(
            "EXEC_STATE_UNBACKED", "coverage.execution_reason_code",
            "nothing was run, and the reason says otherwise"))
    # R2. An executed count needs a measured state AND the run beneath it. `not_run` is only one
    # of the ways to have no run: unavailable, unknown and missing states may not carry a pass.
    if measured_cov and not bound and isinstance(part, dict) and any(
            part.get(k) for k in ("passed", "failed", "refused", "errored")):
        findings.append(Finding(
            "EXEC_STATE_UNBACKED", "coverage.execution_partition",
            "an executed count with no measured execution state and no run document beneath it"))
    # R1. Every route's execution block is checked, and none stands without a run.
    findings += _validate_route_blocks(report, run if bound else None)
    if not valid_shape or not measured_cov:
        return findings

    header, records = run["header"], run["records"]
    drivable = coverage.get("drivable_ids") or []
    routes = [r for r in (report.get("routes") or []) if isinstance(r, dict)]
    route_entry = next((r for r in routes if r.get("name") == "proxy_strict"), {})

    # V1
    if header.get("schema") != schema.EXEC_RUN_SCHEMA:
        findings.append(Finding("EXEC_RECORD_SCHEMA", "execution_run.header.schema",
                                f"{header.get('schema')!r} is not run schema {schema.EXEC_RUN_SCHEMA}"))
    seen = set()
    for index, record in enumerate(records):
        path = f"execution_run.records[{index}]"
        problem = schema.record_shape_problem(record)
        if problem:
            findings.append(Finding("EXEC_RECORD_SCHEMA", path,
                                    f"the record cannot be read, {problem}"))
            outcome = record.get("outcome") if isinstance(record, dict) else None
            if not isinstance(outcome, str) or outcome not in schema.EXEC_STATES or (
                    outcome == "not_run"):
                findings.append(Finding(
                    "EXEC_OUTCOME_UNKNOWN", f"{path}.outcome",
                    f"{outcome!r} is not an executed outcome. `not_run` is the absence of a "
                    "record"))
            continue
        variant_id = record.get("variant_id")
        if record.get("record_schema") != schema.EXEC_RECORD_SCHEMA:
            findings.append(Finding("EXEC_RECORD_SCHEMA", f"{path}.record_schema",
                                    f"{record.get('record_schema')!r} is not record schema "
                                    f"{schema.EXEC_RECORD_SCHEMA}"))
        # V2
        if variant_id not in drivable:
            findings.append(Finding(
                "EXEC_RECORD_NOT_DRIVABLE", f"{path}.variant_id",
                f"{variant_id!r} is not a drivable variant of this corpus, so the run was not "
                "made against this report's planning"))
        if variant_id in seen:
            findings.append(Finding("DUPLICATE_IDS", f"{path}.variant_id",
                                    f"{variant_id!r} has two records and would be counted twice"))
        seen.add(variant_id)
        # V3
        if (record.get("route") != "proxy_strict"
                or record.get("implementation_kind") != "harness_stand_in"
                or route_entry.get("implementation_kind") != "harness_stand_in"):
            findings.append(Finding(
                "EXEC_RECORD_KIND", path,
                f"route {record.get('route')!r} and kind {record.get('implementation_kind')!r} "
                "are not the harness stand in, or the report's route entry is not one. The driver "
                "runs the stand in and nothing else"))
        # V4
        outcome, reason = record.get("outcome"), record.get("reason_code")
        if outcome not in schema.EXEC_STATES or outcome == "not_run":
            findings.append(Finding(
                "EXEC_OUTCOME_UNKNOWN", f"{path}.outcome",
                f"{outcome!r} is not an executed outcome. `not_run` is the absence of a record"))
        if outcome != "passed" and not reason:
            findings.append(Finding("REASON_CODE_MISSING", f"{path}.reason_code",
                                    f"outcome {outcome!r} with no reason code"))
        if reason and reason not in schema.REASON_CODES:
            findings.append(Finding("REASON_CODE_UNKNOWN", f"{path}.reason_code", repr(reason)))
        # V5
        head = record.get("harness_head")
        if not FULL_SHA.match(str(head or "")) or head != header.get("harness_head"):
            findings.append(Finding(
                "IDENTITY_UNPINNED", f"{path}.harness_head",
                f"{head!r} is not a full commit equal to the run header's"))
        # V6, the per record half
        if not record.get("delivered_digest") and not (
                outcome == "errored"
                or (outcome == "refused" and reason == "EVIDENCE_UNBOUND")):
            findings.append(Finding(
                "EXEC_RUN_STALE_CORPUS", f"{path}.delivered_digest",
                "no delivered digest, so this variant is not bound to the delivered corpus"))
        # V8
        if outcome == "passed":
            control = record.get("control") or {}
            evidence = record.get("assertions") or {}
            expectation = record.get("expectation") or {}
            if control.get("stimulus_delivered") is not True:
                findings.append(Finding(
                    "PASSED_WITHOUT_STIMULUS_PROOF", f"{path}.control",
                    "passed with no proof that the hostile stimulus reached the client on the "
                    "route with no mediation. An unplayed scenario also leaves nothing behind"))
            if not record.get("graded_on") or not evidence.get("held"):
                findings.append(Finding(
                    "PASSED_WITHOUT_SUBJECT", f"{path}.graded_on",
                    "passed with nothing graded and no check that held. No assertion failing is "
                    "not the same as one holding"))
            if (evidence.get("not_held")
                    or (expectation.get("assert_original_payload_absent") is True
                        and evidence.get("payload_at_destination") is not False)
                    or (evidence.get("expect_original") is True
                        and evidence.get("declared_frames_delivered_unchanged") is not True)):
                findings.append(Finding(
                    "PASSED_CONTRADICTED", f"{path}.assertions",
                    "passed while the record's own evidence says a check did not hold, or says "
                    "the payload the seed requires absent reached its destination"))
        # V9
        if (record.get("control") or {}).get("stimulus_delivered") is not True and outcome in (
                "passed", "failed"):
            findings.append(Finding(
                "EXEC_UNPROVEN_COUNTED", f"{path}.outcome",
                f"{outcome} with an unproven stimulus. A variant whose control did not deliver "
                "the stimulus is refused, so the count of refusals is never below the unproven"))
        # V14, the record half
        if ROUTE_ROW_KEYS & set(record):
            findings.append(Finding(
                "STANDIN_CLAIMED_AS_ROUTE", path,
                f"a driver record carries {sorted(ROUTE_ROW_KEYS & set(record))}, which read as "
                "route conformance. The stand in is an instrument, not the product"))

    # V5, the header half
    for key in ("harness_head", "engine_head"):
        if not FULL_SHA.match(str(header.get(key) or "")):
            findings.append(Finding("IDENTITY_UNPINNED", f"execution_run.header.{key}",
                                    f"{header.get(key)!r} is not a full commit"))
    pin = identities.get("engine_head")
    if not FULL_SHA.match(str(pin or "")) or header.get("engine_head") != pin:
        findings.append(Finding(
            "IDENTITY_UNPINNED", "execution_run.header.engine_head",
            "the run's engine commit is not the engine commit this report is pinned to. A run "
            "document cannot name the engine it is judged against"))
    if identities.get("execution_harness_head") != header.get("harness_head"):
        findings.append(Finding("IDENTITY_UNPINNED", "identities.execution_harness_head",
                                "does not equal the run header's harness head"))
    # V6, the header half
    if header.get("corpus_digest") != identities.get("corpus_digest") or not header.get("corpus_digest"):
        findings.append(Finding(
            "EXEC_RUN_STALE_CORPUS", "execution_run.header.corpus_digest",
            "the run was made against a different corpus than this report was planned from"))
    if header.get("adapter_digest") != identities.get("adapter_source_digest") or not header.get(
            "adapter_digest"):
        findings.append(Finding(
            "EXEC_RUN_STALE_CODE", "execution_run.header.adapter_digest",
            "the run was made with different adapter code than this report was planned with"))

    # V7. Both the header's counts and the report's partition recomputed from the records.
    drivable_set = set(drivable)
    counted = {"passed": 0, "failed": 0, "refused": 0, "errored": 0}
    once = set()
    for record in records:
        if (isinstance(record, dict) and isinstance(record.get("variant_id"), str)
                and record.get("variant_id") in drivable_set
                and record.get("variant_id") not in once and record.get("outcome") in counted):
            once.add(record["variant_id"])
            counted[record["outcome"]] += 1
    if header.get("counts") != counted:
        findings.append(Finding("AGGREGATE_MISMATCH", "execution_run.header.counts",
                                f"declared {header.get('counts')}, recomputed {counted}"))
    part = coverage.get("execution_partition") or {}
    total = coverage.get("total")
    if isinstance(total, int):
        expected = dict(counted, not_run=total - sum(counted.values()))
        for key, value in expected.items():
            if part.get(key) != value:
                findings.append(Finding(
                    "AGGREGATE_MISMATCH", f"coverage.execution_partition.{key}",
                    f"the report says {part.get(key)}; recomputing from the records beneath it "
                    f"gives {value}"))

    # V10, V11
    if header.get("records_digest") != schema.records_digest(records):
        findings.append(Finding("EXEC_RECORDS_DIGEST", "execution_run.header.records_digest",
                                "does not recompute from the records beneath it"))
    if identities.get("execution_run_digest") != schema.canonical_digest(run):
        findings.append(Finding("EXEC_RUN_DIGEST", "identities.execution_run_digest",
                                "does not equal the digest of the run document in this report"))
    # V13
    fresh = report.get("freshness") or {}
    finished, measured = _when(header.get("finished_at")), _when(fresh.get("measured_at"))
    policy = fresh.get("policy_hours")
    if (finished is None or measured is None or not isinstance(policy, (int, float))
            or measured - finished > datetime.timedelta(hours=policy)
            or finished > measured
            or finished > datetime.datetime.now(datetime.timezone.utc)):
        findings.append(Finding(
            "EXEC_RUN_STALE", "execution_run.header.finished_at",
            "the run is older than the freshness policy allows, finished after the measurement "
            "that carries it or after now, or its date cannot be read. Republishing an old run "
            "does not refresh it"))
    return findings


def _validate_route_blocks(report, run) -> list[Finding]:
    """V12 and V14, the route half, for EVERY route that carries an execution block.

    The block says what ran and carries the sentence that states what the examiner's finding
    covers. It is data the page prints, so it is validated wherever the page can print it: a block
    with no run beneath it, or on a route the run did not execute, is a claim nothing backs.
    """
    findings: list[Finding] = []
    routes = report.get("routes")
    if not isinstance(routes, list):
        return findings
    header = run["header"] if run is not None else {}
    for index, route in enumerate(routes):
        if not isinstance(route, dict) or "execution" not in route:
            continue
        path, block = f"routes[{index}].execution", route["execution"]
        if run is None:
            findings.append(Finding(
                "EXEC_STATE_UNBACKED", path,
                "an execution block with no run document beneath it. Counts and a scope "
                "sentence that nothing ran are the claim this page exists to refuse"))
            continue
        if not isinstance(block, dict) or block.get("state") != "measured":
            findings.append(Finding("EXEC_STATE_UNBACKED", path,
                                    "the execution block is not a measured block of the run"))
            continue
        if route.get("name") != header.get("route") or route.get(
                "implementation_kind") != "harness_stand_in":
            findings.append(Finding(
                "EXEC_RECORD_KIND", path,
                "the block sits on a route the run did not execute, or one that is not the "
                "harness stand in"))
        if ROUTE_ROW_KEYS & set(block):
            findings.append(Finding(
                "STANDIN_CLAIMED_AS_ROUTE", path,
                f"the execution block carries {sorted(ROUTE_ROW_KEYS & set(block))}"))
        if block.get("fit_scope") != schema.STANDIN_SCOPE_SENTENCE:
            findings.append(Finding(
                "STANDIN_SCOPE_MISSING", f"{path}.fit_scope",
                "the route's execution block does not carry the sentence that states what the "
                "examiner's finding covers. Executed variants beside a FIT word read as an "
                "examined executor, and this one was not"))
        if (block.get("records_digest") != header.get("records_digest")
                or block.get("counts") != header.get("counts")
                or block.get("harness_head") != header.get("harness_head")):
            findings.append(Finding("AGGREGATE_MISMATCH", path,
                                    "the block does not equal the run header it summarises"))
    # The route the run executed must say so. This is the old rule, kept: a run is embedded and
    # the route entry does not say what ran.
    if run is not None:
        executed = [r for r in routes if isinstance(r, dict) and r.get("name") == "proxy_strict"]
        if not executed or not isinstance(executed[0].get("execution"), dict) or executed[
                0]["execution"].get("state") != "measured":
            findings.append(Finding(
                "EXEC_STATE_UNBACKED", "routes[proxy_strict].execution",
                "a run is embedded and the route entry does not say what ran"))
    return findings


def _digest_or_none(doc) -> str | None:
    try:
        return schema.canonical_digest(doc)
    except (TypeError, ValueError):
        return None


def _validate_ledger(report) -> list[Finding]:
    """Two labelled lines, each with its own scope, built from a record and never typed.

    Until this existed the panel passed validation if it was any object at all, so a bare number
    under any label would have published. The scope is the whole point: the delivered ledger
    counts the charges of ONE run, and under the cumulative cap's label it would have been a
    scope error wearing a citation.
    """
    findings: list[Finding] = []
    panel = report.get("ledger")
    if isinstance(panel, dict) and panel.get("state") not in schema.NUMERIC_STATES:
        if panel.get("lines"):
            findings.append(Finding(
                "LEDGER_COUNT_INVALID", "ledger.lines",
                "labelled lines beneath a panel whose state states no numbers. A state is not a "
                "number, and lines under it would print one"))
        return findings
    if not isinstance(panel, dict):
        return findings
    run = report.get("execution_run") if isinstance(report.get("execution_run"), dict) else None
    header = (run or {}).get("header") if isinstance((run or {}).get("header"), dict) else {}
    measured = _when((report.get("freshness") or {}).get("measured_at"))

    if panel.get("unit") != schema.LEDGER_UNIT:
        findings.append(Finding(
            "LEDGER_UNIT_WRONG", "ledger.unit",
            f"{panel.get('unit')!r} is not {schema.LEDGER_UNIT!r}. A count is not dollars and "
            "not provider requests"))
    lines = panel.get("lines")
    if not isinstance(lines, list) or not lines:
        findings.append(Finding("LEDGER_LINES_MISSING", "ledger.lines",
                                "a numeric ledger panel with no labelled lines beneath it"))
        return findings
    scopes = [line.get("scope") for line in lines if isinstance(line, dict)]
    for needed in ("cumulative_gate2", "no_live_calls_standin_run"):
        if needed not in scopes:
            findings.append(Finding(
                "LEDGER_LINES_MISSING", "ledger.lines",
                f"no line for scope {needed!r}. The two lines are shown together or the reader "
                "takes the one that is shown for the whole"))

    for index, line in enumerate(lines):
        path = f"ledger.lines[{index}]"
        if not isinstance(line, dict):
            findings.append(Finding("LEDGER_COUNT_INVALID", path, "a line is not an object"))
            continue
        scope = line.get("scope")
        if scope not in schema.LEDGER_SCOPES:
            findings.append(Finding("LEDGER_SCOPE_UNKNOWN", f"{path}.scope",
                                    f"{scope!r} is not in {list(schema.LEDGER_SCOPES)}"))
        if line.get("state") == "unavailable":
            if line.get("reason_code") not in schema.REASON_CODES:
                findings.append(Finding("REASON_CODE_MISSING", path,
                                        "an unavailable line with no reason code in the closed set"))
            carried = sorted(set(line) - {"scope", "state", "reason_code", "source", "text"})
            if carried:
                findings.append(Finding("LEDGER_COUNT_INVALID", path,
                                        f"an unavailable line that still carries {carried}"))
            if line.get("text") is not None:
                findings.append(Finding(
                    "LEDGER_LINE_TYPED", f"{path}.text",
                    "an unavailable line with words on it. A line with no record has no text, "
                    "and text beside a state is a number nobody can trace"))
            continue
        charges, cap, unsettled = line.get("charges"), line.get("cap"), line.get("unsettled")
        needs_cap = scope in ("cumulative_gate2", "live_driver_batch")
        if (not _is_count(charges)
                or (needs_cap and (not _is_count(cap) or not _is_count(unsettled)))
                or (cap is not None and not _is_count(cap))
                or (_is_count(cap) and _is_count(charges) and charges > cap)):
            findings.append(Finding(
                "LEDGER_COUNT_INVALID", path,
                f"charges {charges!r}, cap {cap!r}, unsettled {unsettled!r}. Counts are "
                "non negative whole numbers and charges never exceed the cap"))
        updated = _when(line.get("updated_at"))
        if updated is None or (measured is not None and updated > measured):
            findings.append(Finding(
                "LEDGER_UNDATED", f"{path}.updated_at",
                "a count with no date, or dated after the measurement that carries it"))
        # The words are generated. A hand typed line is a number nobody can trace.
        if line.get("text") != schema.ledger_line_text(line):
            findings.append(Finding(
                "LEDGER_LINE_TYPED", f"{path}.text",
                f"the line reads {line.get('text')!r} and its own fields say "
                f"{schema.ledger_line_text(line)!r}"))
        # An import, not a mint.
        if line.get("source") == "ledger_record":
            record = panel.get("record")
            if (not isinstance(record, dict) or not panel.get("record_digest")
                    or _digest_or_none(record) != panel.get("record_digest")
                    or line.get("record_digest") != panel.get("record_digest")
                    or any(record.get(k) != line.get(k)
                           for k in ("scope", "cap", "charges", "unsettled", "updated_at"))):
                findings.append(Finding(
                    "LEDGER_NOT_IMPORTED", path,
                    "the line is not the imported ledger record it cites"))
        elif line.get("source") == "execution_run":
            ledger_header = header.get("ledger") if isinstance(header.get("ledger"), dict) else {}
            if (run is None or line.get("records_digest") != header.get("records_digest")
                    or line.get("run_id") != header.get("run_id")
                    or line.get("updated_at") != header.get("finished_at")
                    or ledger_header.get("scope") != scope
                    or ledger_header.get("charges") != charges):
                findings.append(Finding(
                    "LEDGER_NOT_IMPORTED", path,
                    "the line is not the ledger block of the run document in this report"))
        else:
            findings.append(Finding("LEDGER_NOT_IMPORTED", f"{path}.source",
                                    f"{line.get('source')!r} is not an imported record"))
        # The zero trap. A zero is readable only where the scope says why it is zero.
        if charges == 0 and scope != "no_live_calls_standin_run":
            findings.append(Finding(
                "LEDGER_ZERO_UNSCOPED", f"{path}.charges",
                "a zero count under a scope that does not say why it is zero reads as 'nothing "
                "spent' when it may be 'nothing counted'"))
        # A stand in run made no live call, and a run that made some is not a stand in run.
        if scope == "live_driver_batch" and run is not None:
            findings.append(Finding(
                "LEDGER_SCOPE_CONTRADICTED", f"{path}.scope",
                "a stand in run carries a live driver batch scope"))
        if scope == "no_live_calls_standin_run" and charges not in (0, None):
            findings.append(Finding(
                "LEDGER_SCOPE_CONTRADICTED", f"{path}.charges",
                f"scope says no live calls and the count is {charges!r}"))
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


# Elements whose text a reader is never shown, and the markup that hides one that is. A binding
# there can hold any text at all, because nobody reads it.
NON_VISIBLE_TAGS = frozenset({"script", "style", "template", "title", "textarea", "noscript",
                              "head", "iframe", "object"})
VOID_TAGS = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
                       "source", "track", "wbr"})
HIDING_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*(?:hidden|collapse)|opacity\s*:\s*0(?![.\d])"
    r"|font-size\s*:\s*0(?![.\d])|color\s*:\s*transparent"
    r"|(?:left|top|text-indent)\s*:\s*-\d{3,}|clip-path\s*:\s*inset\(\s*50%", re.I)


class _Bindings(HTMLParser):
    """Every `data-bound` element with the text a browser would show for it.

    A parser and not a pattern, because the pattern read only up to the first nested tag, and
    because entity decoding belongs to the context: text in a script or style element is raw, and
    text in a visible element is decoded. `convert_charrefs` does exactly that.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[dict] = []
        self.found: list[dict] = []
        self.hiding_rules: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        hides = ("hidden" in attrs or (attrs.get("aria-hidden") or "").strip().lower() == "true"
                 or bool(HIDING_STYLE.search(attrs.get("style") or ""))
                 or tag in NON_VISIBLE_TAGS)
        parent_dark = bool(self.stack) and self.stack[-1]["dark"]
        entry = {"tag": tag, "dark": parent_dark or hides, "hides": hides,
                 "path": attrs.get("data-bound"), "text": []}
        if tag in VOID_TAGS:
            if entry["path"] is not None:
                self.found.append(entry)
            return
        self.stack.append(entry)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID_TAGS and self.stack and self.stack[-1]["tag"] == tag:
            self._close(len(self.stack) - 1)

    def handle_data(self, data):
        """Text counts toward a bound element only when nothing between that element and the text
        hides it. A hidden, aria hidden, script, style or template descendant is the element's own
        concealed text, not its displayed text, so it is left out of what the element shows."""
        if self.stack and self.stack[-1]["tag"] == "style":
            self.handle_style_text(data)
        for index, entry in enumerate(self.stack):
            if entry["path"] is not None and not any(
                    inner["hides"] for inner in self.stack[index + 1:]):
                entry["text"].append(data)

    def handle_style_text(self, text):
        if HIDING_STYLE.search(text):
            self.hiding_rules.append(text)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index]["tag"] == tag:
                self._close(index)
                return

    def _close(self, index):
        while len(self.stack) > index:
            entry = self.stack.pop()
            if entry["path"] is not None:
                self.found.append(entry)

    def close(self):
        super().close()
        self._close(0)


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


def _required_bindings(report: dict) -> list[str]:
    """Fields the page must show as bound figures or text, derived from the report alone. A page
    that drops one of them cannot be told from one whose renderer never had it."""
    need: list[str] = []
    routes = report.get("routes")
    for index, route in enumerate(routes if isinstance(routes, list) else []):
        block = route.get("execution") if isinstance(route, dict) else None
        if isinstance(block, dict):
            need.append(f"routes[{index}].execution.fit_scope")
            need += [f"routes[{index}].execution.counts.{key}"
                     for key in sorted(block["counts"])] if isinstance(
                         block.get("counts"), dict) else []
    ledger = report.get("ledger")
    if isinstance(ledger, dict) and schema.numeric_readable(ledger) and isinstance(
            ledger.get("lines"), list):
        need += [f"ledger.lines[{index}].text" for index, line in enumerate(ledger["lines"])
                 if isinstance(line, dict) and line.get("text") is not None]
    coverage = report.get("coverage")
    if isinstance(coverage, dict) and schema.numeric_readable(coverage) and isinstance(
            coverage.get("execution_partition"), dict):
        need += ["coverage.execution_partition.passed", "coverage.execution_partition.not_run"]
    return need


def check_transcription(html: str, report: dict) -> list[Finding]:
    """Every rendered figure equals the validated artifact it cites.

    This is the weaker of the two checks and is labelled as such, because a
    coordinated edit to both files passes it. It exists to catch the renderer,
    not the author. It reads the page as a browser does: the text of a bound
    element is all of its text after the entities in it are decoded, a binding
    inside an element nobody sees is refused, and the fields the report says
    must be on the page must be bound there.
    """
    findings: list[Finding] = []
    parser = _Bindings()
    parser.feed(html)
    parser.close()
    visible: set[str] = set()
    if parser.hiding_rules:
        findings.append(Finding(
            "BINDING_NOT_VISIBLE", "html.style",
            "a style sheet on the page hides content. The page the renderer writes has no such "
            "rule, and one here can conceal any bound text that a browser would otherwise show"))
    for entry in parser.found:
        path = entry["path"]
        if entry["dark"]:
            findings.append(Finding(
                "BINDING_NOT_VISIBLE", path,
                f"the binding sits in a {entry['tag']!r} element or under one that is hidden. "
                "Text nobody is shown can say anything, so it proves nothing about the page"))
            continue
        visible.add(path)               # shown, so not missing. A wrong text is reported below
        try:
            value = resolve(report, path)
        except (KeyError, IndexError, TypeError, ValueError):
            findings.append(Finding("BOUND_PATH_MISSING", path,
                                    "the page cites a field the artifact lacks"))
            continue
        shown = "".join(entry["text"]).strip()
        if str(value) != shown:
            findings.append(Finding(
                "TRANSCRIPTION_MISMATCH", path,
                f"the page shows {shown!r}; the artifact says {value!r}"))
    if not parser.found:
        findings.append(Finding(
            "NOTHING_BOUND", "html",
            "no rendered figure cites an artifact field. An unbound page is a "
            "page of hand-typed numbers, which is the defect this exists for."))
    for path in _required_bindings(report):
        if path not in visible:
            findings.append(Finding(
                "BINDING_MISSING", path,
                "the report carries this field and the page does not show it bound to it"))
    return findings
