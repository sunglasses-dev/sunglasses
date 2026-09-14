"""A control for every remaining guard, because an untested guard rots quietly.

E10 froze twelve acceptance controls and those live next door in
`test_acceptance_controls.py`. Writing them left 27 of this validator's 44
guards with no control at all: they were written, they looked right, and nothing
would have noticed if one stopped firing. That gap was found by mutating each
guard's finding code and watching which controls went red, and the first run of
that sweep reported 42 of 44 unguarded because the mutation never applied to a
multi line call. A green mutation row is a harness defect until the stimulus is
proven, same as a red one.

So each test below mutates the artifact in the one way its guard exists to
catch, and asserts that guard's exact code.
"""
import copy
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[1] / "boundary"))

import produce                                             # noqa: E402
import render                                              # noqa: E402
import validate                                            # noqa: E402


def codes(findings):
    return {f.code for f in findings}


@pytest.fixture(scope="module")
def honest():
    report, _ = produce.build(run_id="fixture")
    return report


def mutate(honest, path, value):
    """Set one dotted path and return the whole artifact."""
    mutated = copy.deepcopy(honest)
    node = mutated
    parts = path.split(".")
    for part in parts[:-1]:
        if part.endswith("]") and "[" in part:
            name, index = part[:-1].split("[")
            node = node[name][int(index)]
        else:
            node = node[part]
    node[parts[-1]] = value
    return mutated


# --- the artifact as a whole -----------------------------------------------

def test_an_unknown_schema_version_stops_everything(honest):
    assert "SCHEMA_UNKNOWN" in codes(validate.validate_report(mutate(honest, "schema", 99)))


def test_a_panel_that_is_not_an_object_is_rejected(honest):
    assert "PANEL_NOT_AN_OBJECT" in codes(
        validate.validate_report(mutate(honest, "harness", "all good")))


def test_an_unknown_state_word_is_not_a_third_answer(honest):
    assert "UNKNOWN_STATE" in codes(
        validate.validate_report(mutate(honest, "harness.state", "mostly_fine")))


def test_a_reason_code_outside_the_closed_set_is_rejected(honest):
    assert "REASON_CODE_UNKNOWN" in codes(
        validate.validate_report(mutate(honest, "harness.reason_code", "IT_IS_FINE")))


def test_an_unavailable_panel_must_say_why(honest):
    mutated = copy.deepcopy(honest)
    mutated["harness"].pop("reason_code")
    assert "REASON_CODE_MISSING" in codes(validate.validate_report(mutated))


# --- the run ---------------------------------------------------------------

def test_a_run_missing_its_identity_is_rejected(honest):
    mutated = copy.deepcopy(honest)
    mutated["run"].pop("id")
    assert "RUN_INCOMPLETE_IDENTITY" in codes(validate.validate_report(mutated))


def test_an_unknown_outcome_word_is_rejected(honest):
    assert "RUN_OUTCOME_UNKNOWN" in codes(
        validate.validate_report(mutate(honest, "run.outcome", "finished-ish")))


def test_a_complete_run_reporting_failure_is_rejected(honest):
    mutated = mutate(honest, "run.outcome", "complete")
    mutated["run"]["exit_code"] = 7
    assert "COMPLETE_EXITED_NONZERO" in codes(validate.validate_report(mutated))


# --- freshness -------------------------------------------------------------

def test_the_policy_must_travel_with_the_artifact(honest):
    """Otherwise the page enforces one limit and claims another."""
    assert "FRESHNESS_POLICY_MISSING" in codes(
        validate.validate_report(mutate(honest, "freshness.policy_hours", None)))


def test_generation_time_cannot_stand_in_for_measurement_time(honest):
    assert "FRESHNESS_NO_MEASURED_AT" in codes(
        validate.validate_report(mutate(honest, "freshness.measured_at", None)))


# --- coverage partitions ---------------------------------------------------

def test_a_variant_in_two_partitions_is_rejected(honest):
    mutated = copy.deepcopy(honest)
    both = mutated["coverage"]["blocked_ids"][0]
    mutated["coverage"]["drivable_ids"].append(both)
    mutated["coverage"]["plan_partition"]["drivable"] += 1
    mutated["coverage"]["total"] += 1
    assert "MEMBERSHIP_OVERLAP" in codes(validate.validate_report(mutated))


def test_a_total_that_is_not_the_sum_of_its_parts_is_rejected(honest):
    assert "TOTAL_MISMATCH" in codes(
        validate.validate_report(mutate(honest, "coverage.total", 200)))


def test_an_execution_partition_missing_a_state_is_rejected(honest):
    mutated = copy.deepcopy(honest)
    mutated["coverage"]["execution_partition"].pop("refused")
    assert "EXEC_PARTITION_INCOMPLETE" in codes(validate.validate_report(mutated))


def test_an_execution_partition_that_does_not_sum_is_rejected(honest):
    assert "EXEC_PARTITION_MISMATCH" in codes(
        validate.validate_report(
            mutate(honest, "coverage.execution_partition.not_run", 3)))


def test_more_passes_than_were_ever_drivable_is_rejected(honest):
    """Planning is not execution, and execution cannot exceed it."""
    mutated = copy.deepcopy(honest)
    plan = mutated["coverage"]["plan_partition"]
    execution = mutated["coverage"]["execution_partition"]
    execution["passed"] = plan["drivable"] + 5
    execution["not_run"] = mutated["coverage"]["total"] - execution["passed"]
    assert "EXEC_EXCEEDS_PLAN" in codes(validate.validate_report(mutated))


# --- the ceiling -----------------------------------------------------------

def test_a_coverage_panel_with_no_ceiling_is_rejected(honest):
    mutated = copy.deepcopy(honest)
    mutated["coverage"].pop("ceiling")
    assert "CEILING_ABSENT" in codes(validate.validate_report(mutated))


def test_an_unknown_ceiling_state_is_rejected(honest):
    assert "CEILING_STATE_UNKNOWN" in codes(
        validate.validate_report(mutate(honest, "coverage.ceiling.state", "probably")))


def test_a_refusal_must_name_how_many_things_it_could_not_classify(honest):
    assert "REFUSAL_WITHOUT_CAUSE" in codes(
        validate.validate_report(
            mutate(honest, "coverage.ceiling.unclassified_count", 0)))


def test_not_applicable_beside_blocked_variants_is_rejected(honest):
    """The question plainly does arise when 47 variants are blocked."""
    mutated = copy.deepcopy(honest)
    mutated["coverage"]["ceiling"] = {
        "state": "not_applicable", "reason_code": "CEILING_NO_BLOCKED_VARIANTS",
        "blocked_needing_route": None, "blocked_by_adapter_work_alone": None}
    assert "CEILING_NOT_APPLICABLE_WITH_BLOCKERS" in codes(
        validate.validate_report(mutated))


def test_a_computed_ceiling_with_no_subtotals_is_rejected(honest):
    mutated = copy.deepcopy(honest)
    mutated["coverage"]["ceiling"] = {
        "state": "true", "reason_code": "CEILING_ALL_BLOCKED_NEED_ROUTE",
        "blocked_needing_route": None, "blocked_by_adapter_work_alone": None}
    assert "CEILING_SUBTOTALS_MISSING" in codes(validate.validate_report(mutated))


# --- routes and rows -------------------------------------------------------

def test_an_artifact_with_no_routes_array_is_rejected(honest):
    assert "ROUTES_ABSENT" in codes(validate.validate_report(mutate(honest, "routes", None)))


def test_the_same_route_twice_is_rejected(honest):
    mutated = copy.deepcopy(honest)
    mutated["routes"].append(copy.deepcopy(mutated["routes"][0]))
    assert "DUPLICATE_ROUTE" in codes(validate.validate_report(mutated))


def test_a_numeric_rows_panel_with_no_per_row_results_is_rejected(honest):
    mutated = copy.deepcopy(honest)
    mutated["routes"][0].update({
        "implementation_kind": "product_candidate", "head": "c" * 40,
        "rows": {"state": "measured", "total": 2}})
    assert "ROWS_WITHOUT_MANIFEST" in codes(validate.validate_report(mutated))


def test_an_unknown_row_state_is_rejected(honest):
    mutated = copy.deepcopy(honest)
    mutated["routes"][0].update({
        "implementation_kind": "product_candidate", "head": "c" * 40,
        "rows": {"state": "measured", "total": 1,
                 "row_results": {"T1.R2": {"state": "nearly", "evidence": "e"}}}})
    assert "ROW_STATE_UNKNOWN" in codes(validate.validate_report(mutated))


def test_a_row_total_that_hides_a_missing_row_is_rejected(honest):
    mutated = copy.deepcopy(honest)
    mutated["routes"][0].update({
        "implementation_kind": "product_candidate", "head": "c" * 40,
        "rows": {"state": "measured", "total": 8,
                 "row_results": {"T1.R2": {"state": "conformant",
                                           "evidence": "ev/1"}}}})
    assert "TOTAL_MISMATCH" in codes(validate.validate_report(mutated))


def test_an_undated_examination_reads_as_current_and_is_rejected(honest):
    mutated = copy.deepcopy(honest)
    mutated["harness"] = {
        "state": "historical", "record_digest": "d" * 64,
        "record": {"met": 7, "of": 7, "exam_head": "a" * 40}}
    assert "FIT_UNDATED" in codes(validate.validate_report(mutated))


# --- the page against the artifact -----------------------------------------

def test_a_page_citing_a_field_the_artifact_lacks_is_rejected(honest):
    page = render.render(honest)
    broken = page.replace('data-bound="run.id"', 'data-bound="run.no_such_field"')
    assert broken != page, "the mutation did not apply; the control is vacuous"
    assert "BOUND_PATH_MISSING" in codes(validate.check_transcription(broken, honest))


def test_a_page_that_cites_nothing_is_rejected(honest):
    """An unbound page is a page of hand typed numbers, which is the whole point."""
    assert "NOTHING_BOUND" in codes(
        validate.check_transcription("<p>everything is fine</p>", honest))
