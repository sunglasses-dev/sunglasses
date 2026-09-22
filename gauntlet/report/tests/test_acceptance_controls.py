"""The twelve controls from E10, each one a mutation that must be rejected.

Every test here asserts a SPECIFIC finding code rather than "something was
found". A test that only checks the list is non-empty passes for any reason at
all, including a typo in the fixture, and would have let a broken guard ship
looking green. The Sep-13 law applies to this file in particular: a check that
can skip itself is worse than no check, so each control names the exact defect
it is supposed to catch.

Where a control has two halves that must be caught by DIFFERENT machinery, it is
two tests, because a single assertion could otherwise be satisfied by whichever
half is easier.
"""
import copy
import datetime
import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[1] / "boundary"))

import classify                                            # noqa: E402
import produce                                             # noqa: E402
import publish                                             # noqa: E402
import render                                              # noqa: E402
import validate                                            # noqa: E402


def codes(findings):
    return {f.code for f in findings}


@pytest.fixture(scope="module")
def honest():
    """Today's real artifact, built by the producer from live measurement."""
    report, _ = produce.build(run_id="fixture")
    return report


@pytest.fixture(scope="module")
def capmap():
    return classify.load_map()


def test_the_honest_artifact_validates(honest):
    """The baseline. A mutation test on a red baseline proves nothing."""
    assert validate.validate_report(honest) == []


# --- control 1 -------------------------------------------------------------
# "Change a rendered value; then change JSON and HTML together while underlying
#  rows stay fixed. Both rejected: transcription and independent aggregation
#  are separate checks."

def test_c1_changing_only_the_page_is_caught_by_transcription(honest):
    page = render.render(honest)
    target = str(honest["coverage"]["plan_partition"]["drivable"])
    mutated = page.replace(
        f'data-bound="coverage.plan_partition.drivable">{target}<',
        'data-bound="coverage.plan_partition.drivable">99<')
    assert mutated != page, "the mutation did not apply; the control is vacuous"
    assert "TRANSCRIPTION_MISMATCH" in codes(
        validate.check_transcription(mutated, honest))


def test_c1_changing_json_and_page_together_is_caught_by_recomputation(honest):
    """The half transcription cannot catch, which is why it is not the only check."""
    mutated = copy.deepcopy(honest)
    mutated["coverage"]["plan_partition"]["drivable"] = 99
    mutated["coverage"]["total"] = 99 + mutated["coverage"]["plan_partition"]["blocked"]
    page = render.render(mutated, findings=[])          # render it anyway
    assert validate.check_transcription(page, mutated) == [], \
        "the page and the artifact agree, so only recomputation can catch this"
    assert "AGGREGATE_MISMATCH" in codes(validate.validate_report(mutated))


# --- control 2 -------------------------------------------------------------
# "Delete/duplicate a failing row/variant; omit a required mutation; relabel
#  partial as full. Completeness/scope validation rejects; score cannot improve."

def test_c2_deleting_a_blocked_variant_cannot_shrink_the_denominator(honest):
    mutated = copy.deepcopy(honest)
    mutated["coverage"]["blocked_ids"].pop()
    assert "AGGREGATE_MISMATCH" in codes(validate.validate_report(mutated))


def test_c2_duplicating_a_variant_is_rejected(honest):
    mutated = copy.deepcopy(honest)
    mutated["coverage"]["drivable_ids"].append(mutated["coverage"]["drivable_ids"][0])
    mutated["coverage"]["plan_partition"]["drivable"] += 1
    mutated["coverage"]["total"] += 1
    assert "DUPLICATE_IDS" in codes(validate.validate_report(mutated))


def test_c2_a_partial_sub_obligation_cannot_count_as_a_full_row(honest):
    mutated = copy.deepcopy(honest)
    mutated["routes"][0].update({
        "implementation_kind": "product_candidate",
        "head": "c" * 40,
        "rows": {"state": "measured", "total": 1,
                 "row_results": {"T4.R4": {"state": "conformant",
                                           "scope": "partial",
                                           "evidence": "ev/1"}}},
    })
    assert "PARTIAL_ROW_COUNTED_FULL" in codes(validate.validate_report(mutated))


# --- control 3 -------------------------------------------------------------
# "Keep a green mutation summary when a mutant survives, never applies, errors,
#  or starts from a red baseline. Survival lowers the score; invalid execution
#  never counts as rejection."

def test_c3_a_perfect_score_with_a_survivor_is_contradicted(honest):
    mutated = copy.deepcopy(honest)
    mutated["harness"] = {
        "state": "historical", "record_digest": "d" * 64,
        "record": {"met": 7, "of": 7, "exam_head": "a" * 40,
                   "examined_at": "2026-09-14",
                   "mutants": {"rejected": 119, "total": 119,
                               "statuses": {"rejected": 118, "survived": 1}}},
    }
    assert "MUTATION_SUMMARY_CONTRADICTED" in codes(validate.validate_report(mutated))


def test_c3_mutants_that_never_applied_are_not_rejections(honest):
    mutated = copy.deepcopy(honest)
    mutated["harness"] = {
        "state": "historical", "record_digest": "d" * 64,
        "record": {"met": 7, "of": 7, "exam_head": "a" * 40,
                   "examined_at": "2026-09-14",
                   "mutants": {"rejected": 119, "total": 119,
                               "statuses": {"rejected": 119, "not_applied": 0,
                                            "errored": 0, "red_baseline": 0}}},
    }
    # A clean one passes, so the control is not passing for an unrelated reason.
    assert "MUTATION_SUMMARY_CONTRADICTED" not in codes(validate.validate_report(mutated))
    # Three mutants that errored. The arithmetic still adds up, and that is
    # exactly the hole the first version of this guard had: it only fired on a
    # PERFECT score, so 119 of 122 with three errors passed silently.
    mutated["harness"]["record"]["mutants"]["statuses"]["errored"] = 3
    mutated["harness"]["record"]["mutants"]["total"] = 122
    assert "MUTATION_SUMMARY_CONTRADICTED" in codes(validate.validate_report(mutated))

    # An examination may still publish, if it says out loud that it is partial.
    mutated["harness"]["record"]["completeness"] = "incomplete"
    assert "MUTATION_SUMMARY_CONTRADICTED" not in codes(
        validate.validate_report(mutated))


def test_c3_fit_cannot_be_minted_without_an_examiner_record(honest):
    mutated = copy.deepcopy(honest)
    mutated["harness"] = {"state": "measured", "met": 7, "of": 7}
    assert "FIT_NOT_IMPORTED" in codes(validate.validate_report(mutated))


# --- control 4 -------------------------------------------------------------
# "Insert unknown op before/after a known blocker and in a would-be drivable
#  schedule; introduce unknown actor/fault selector. Order-independent refusal,
#  distinct unknown IDs/count, null ceiling/subtotals, nonzero run."

KNOWN_BLOCKER = {"op": "invoke_real_doctor", "capture_output": True,
                 "capture_children_and_receipts": True}
UNKNOWN_OP = {"op": "op_no_map_has_ever_seen"}


@pytest.mark.parametrize("steps,label", [
    ([UNKNOWN_OP, KNOWN_BLOCKER], "unknown first"),
    ([KNOWN_BLOCKER, UNKNOWN_OP], "unknown second"),
])
def test_c4_an_unknown_op_refuses_whichever_side_of_a_blocker_it_sits(
        steps, label, capmap):
    """The short circuit, which is why this is parametrised on order.

    The first version of this checked classification inside the loop that
    returns on the first blocker it meets, so `unknown second` read green and
    exited 0. Both orders must reach the same refusal.
    """
    result = classify.classify({"V": steps}, capmap)
    assert not result.complete, f"{label}: the unknown op was not noticed"
    assert "op_no_map_has_ever_seen" in result.uncovered


def test_c4_an_unknown_fault_selector_is_refused_not_bucketed(capmap):
    steps = [{"op": "arm_fault", "kind": "a_kind_nobody_declared",
              "target": "scanner_worker", "require_fresh_barrier": True}]
    result = classify.classify({"V": steps}, capmap)
    key = "arm_fault[kind=a_kind_nobody_declared]"
    assert result.buckets.get(key) == classify.ROUTE, \
        "a kind outside the cited enumeration is a real-route capability"


def test_c4_refusal_publishes_nulls_and_a_nonzero_run(honest):
    ceiling = honest["coverage"]["ceiling"]
    assert ceiling["state"] == "not_computed"
    assert ceiling["blocked_needing_route"] is None
    assert ceiling["blocked_by_adapter_work_alone"] is None
    assert ceiling["unclassified_count"] == len(ceiling["unclassified"])
    assert honest["run"]["exit_code"] != 0
    assert honest["run"]["outcome"] == "refused"


def test_c4_a_refusal_that_exits_zero_is_itself_rejected(honest):
    mutated = copy.deepcopy(honest)
    mutated["run"]["exit_code"] = 0
    assert "REFUSAL_EXITED_ZERO" in codes(validate.validate_report(mutated))


def test_c4_a_refusal_may_not_publish_zero_instead_of_null(honest):
    mutated = copy.deepcopy(honest)
    mutated["coverage"]["ceiling"]["blocked_by_adapter_work_alone"] = 0
    assert "REFUSAL_PUBLISHED_A_NUMBER" in codes(validate.validate_report(mutated))


# --- control 5 -------------------------------------------------------------
# "Malform a schedule or make the planner throw unexpectedly. Invalid
#  planning/report, not 'needs route capability'."

def test_c5_a_malformed_schedule_is_invalid_not_a_capability_blocker(tmp_path):
    root = tmp_path / "materialized"
    (root / "V-bad").mkdir(parents=True)
    (root / "V-bad" / "schedule.json").write_text(json.dumps(
        {"scenario_id": "V", "variant": "bad",
         "profile_steps": [{"op": "send_file"}]}))       # required fields absent
    planned = produce.plan_corpus(root)
    assert "V-bad" in planned["invalid"]
    assert planned["invalid"]["V-bad"]["reason_code"] == "PLAN_INVALID_SCHEDULE"
    assert "V-bad" not in planned["blocked"], \
        "our own malformed input must not be reported as the product's gap"


def test_c5_an_empty_schedule_is_a_missing_document_not_an_empty_run(tmp_path):
    root = tmp_path / "materialized"
    (root / "V-empty").mkdir(parents=True)
    (root / "V-empty" / "schedule.json").write_text(
        json.dumps({"scenario_id": "V", "variant": "empty", "profile_steps": []}))
    planned = produce.plan_corpus(root)
    assert planned["invalid"]["V-empty"]["reason_code"] == "PLAN_INVALID_SCHEDULE"


# --- control 6 -------------------------------------------------------------
# "Demonstrate an adapter-only blocked variant; then no blocked variants. False
#  ceiling with matching explanation; then not-applicable."

def test_c6_an_adapter_only_variant_flips_the_ceiling_to_false(capmap):
    """The falsifiability proof. A derivation that cannot go false is worthless.

    `arm_fault` with a kind the mediator's cited enumeration DOES contain is
    machinery that exists, so the gap is adapter work and the ceiling is false.
    """
    blocked = {"V-adapter-only": [
        {"op": "arm_fault", "kind": "hang", "target": "scanner_worker",
         "require_fresh_barrier": True}]}
    result = classify.classify(blocked, capmap)
    assert result.complete
    assert result.buckets["arm_fault[kind=hang]"] == classify.ADAPTER_ONLY

    panel = produce.coverage_panel(
        {"drivable": [], "blocked": blocked, "invalid": {}}, capmap)
    assert panel["ceiling"]["state"] == "false"
    assert panel["ceiling"]["reason_code"] == "CEILING_ADAPTER_ONLY_MEMBER"
    assert panel["ceiling"]["blocked_by_adapter_work_alone"] == 1
    assert validate.validate_report(
        {**_skeleton(), "coverage": panel}) == []


def test_c6_a_route_only_blocker_gives_a_true_ceiling(capmap):
    """The other answer, so `false` above is not the only reachable one."""
    blocked = {"V-route": [KNOWN_BLOCKER]}
    panel = produce.coverage_panel(
        {"drivable": [], "blocked": blocked, "invalid": {}}, capmap)
    assert panel["ceiling"]["state"] == "true"
    assert panel["ceiling"]["reason_code"] == "CEILING_ALL_BLOCKED_NEED_ROUTE"
    assert panel["ceiling"]["blocked_by_adapter_work_alone"] == 0


def test_c6_no_blocked_variants_is_not_applicable_not_a_vacuous_true(capmap):
    panel = produce.coverage_panel(
        {"drivable": ["V1"], "blocked": {}, "invalid": {}}, capmap)
    assert panel["ceiling"]["state"] == "not_applicable"
    assert panel["ceiling"]["reason_code"] == "CEILING_NO_BLOCKED_VARIANTS"
    assert panel["ceiling"]["blocked_needing_route"] is None


def test_c6_a_true_ceiling_beside_an_adapter_only_variant_is_contradicted(honest):
    mutated = copy.deepcopy(honest)
    mutated["coverage"]["ceiling"] = {
        "state": "true", "reason_code": "CEILING_ALL_BLOCKED_NEED_ROUTE",
        "blocked_needing_route": len(mutated["coverage"]["blocked_ids"]) - 1,
        "blocked_by_adapter_work_alone": 1,
    }
    assert "CEILING_CONTRADICTED" in codes(validate.validate_report(mutated))


# --- control 7 -------------------------------------------------------------
# "Change route identity or remove actual capability while preserving its
#  declared support list. Prior classification/FIT applicability invalidated or
#  behavioral control fails; declaration cannot preserve a claim."

def test_c7_a_declared_support_list_cannot_preserve_a_removed_capability(capmap):
    """The declaration says the event is supported; the enumeration is the map's.

    Removing the capability while leaving the declaration standing must not
    leave the classification reading as though nothing changed.
    """
    stripped = copy.deepcopy(capmap)
    stripped["enumerated_values"]["await_event.event"]["available"] = []
    steps = [{"op": "await_event", "event": "SCAN_STARTED",
              "correlate_id_from": "a.jsonl", "timeout_ms": 1000}]
    before = classify.classify({"V": steps}, capmap)
    after = classify.classify({"V": steps}, stripped)
    assert before.buckets == {} and before.complete, \
        "a supported event is not a remaining need"
    assert after.buckets.get("await_event[event=SCAN_STARTED,actor=proxy]") \
        == classify.ROUTE


def test_c7_a_map_entry_without_evidence_is_refused(capmap):
    broken = copy.deepcopy(capmap)
    broken["classified"]["invoke_real_doctor"].pop("evidence")
    with pytest.raises(classify.MapInvalid, match="no evidence"):
        _reload_map(broken)


def test_c7_an_op_in_both_buckets_is_a_map_defect(capmap):
    broken = copy.deepcopy(capmap)
    broken["unclassified"]["invoke_real_doctor"] = {"open_question": "x"}
    with pytest.raises(classify.MapInvalid, match="both classified"):
        _reload_map(broken)


# --- control 8 -------------------------------------------------------------
# "Product reports success/withheld while independent wires/destination
#  contradict it; disconnect an observer. Valid contradiction is failure;
#  absent observation is invalid/unavailable. Neither earns conformance."

def test_c8_a_contradicted_row_cannot_be_conformant(honest):
    mutated = _with_rows(honest, {"T1.R2": {
        "state": "conformant", "evidence": "ev/1",
        "contradicted_by": "client wire capture"}})
    assert "CONFORMANT_CONTRADICTED" in codes(validate.validate_report(mutated))


def test_c8_a_disconnected_observer_does_not_earn_conformance(honest):
    mutated = _with_rows(honest, {"T1.R2": {
        "state": "conformant", "evidence": "ev/1",
        "observer_state": "disconnected"}})
    assert "CONFORMANT_WITHOUT_OBSERVER" in codes(validate.validate_report(mutated))


def test_c8_a_row_with_no_evidence_is_not_a_pass(honest):
    mutated = _with_rows(honest, {"T1.R2": {"state": "conformant"}})
    assert "CONFORMANT_WITHOUT_EVIDENCE" in codes(validate.validate_report(mutated))


# --- control 9 -------------------------------------------------------------
# "Fail/refuse/crash after successful publication; let an older attempt finish
#  after a newer one. Publish valid failure report, retain nonzero outcome,
#  reject stale overwrite, expire if no report arrives."

def test_c9_a_refusal_replaces_a_published_green_page(honest):
    site = publish.Published()
    green = copy.deepcopy(honest)
    green["run"].update({"outcome": "complete", "exit_code": 0,
                         "finished_at": "2026-09-14T01:00:00+00:00"})
    site.select(green)
    refusal = copy.deepcopy(honest)
    refusal["run"].update({"outcome": "refused", "exit_code": 3,
                           "finished_at": "2026-09-14T02:00:00+00:00"})
    site.select(refusal)
    assert site.report["run"]["outcome"] == "refused", \
        "latest attempt, never latest success"


def test_c9_an_older_attempt_finishing_second_is_refused(honest):
    site = publish.Published()
    newer = copy.deepcopy(honest)
    newer["run"]["finished_at"] = "2026-09-14T02:00:00+00:00"
    site.select(newer)
    older = copy.deepcopy(honest)
    older["run"]["finished_at"] = "2026-09-14T01:00:00+00:00"
    with pytest.raises(publish.StaleOverwrite):
        site.select(older)
    assert site.report["run"]["finished_at"] == "2026-09-14T02:00:00+00:00"
    assert len(site.history) == 2, "a refused attempt is still part of the history"


def test_c9_nothing_published_is_expired_not_green():
    assert publish.Published().expired() is True


# --- control 10 ------------------------------------------------------------
# "Keep identical deployed HTML past its deadline, reload, leave open,
#  disable/break script. No current green or current numeric score after expiry;
#  base/error state unverified."

def test_c10_the_base_html_claims_nothing_current(honest):
    page = render.render(honest)
    head = page.split("<script>")[0]
    assert "unverified" in head
    for word in ("all green", "currently passing", "up to date"):
        assert word not in head.lower()


def test_c10_the_script_can_only_remove_the_caveat(honest):
    """Read the shipped script, not a description of it.

    A build-time-only warning cannot change after publishing stops, so the
    honest text has to be what arrives and the script has to be incapable of
    inventing a green one when it should not.
    """
    page = render.render(honest)
    script = page.split("<script>")[1]
    assert 'd.outcome !== "complete"' in script, \
        "a refused run must never reach the reassuring branch"
    assert "ageHours > d.policy_hours" in script
    assert "ageHours < 0" in script, "a future measurement is invalid, not fresh"


def test_c10_a_stale_publication_is_expired(honest):
    site = publish.Published()
    old = copy.deepcopy(honest)
    old["freshness"]["measured_at"] = "2026-09-01T00:00:00+00:00"
    old["run"]["finished_at"] = "2026-09-01T00:00:00+00:00"
    site.select(old)
    assert site.expired(datetime.datetime(2026, 9, 14,
                                          tzinfo=datetime.timezone.utc)) is True


# --- control 11 ------------------------------------------------------------
# "Lose origin reachability, fail a reachability check, remove archived
#  evidence. Distinct availability states and accurate labels."

def test_c11_reachability_is_three_valued(honest):
    mutated = copy.deepcopy(honest)
    mutated["routes"][0]["head_reachable_on_origin"] = False
    assert "REACHABILITY_STATE_UNKNOWN" in codes(validate.validate_report(mutated))


def test_c11_unknown_is_a_permitted_state_and_unreachable_is_not_gone(honest):
    for state in ("reachable", "unreachable", "unknown"):
        mutated = copy.deepcopy(honest)
        mutated["routes"][0]["head_reachable_on_origin"] = state
        assert "REACHABILITY_STATE_UNKNOWN" not in codes(
            validate.validate_report(mutated))


# --- control 12 ------------------------------------------------------------
# "Switch stand-in -> candidate -> different merged head -> released artifact.
#  No inherited execution score, full-route verdict or release claim without
#  corresponding evidence."

def test_c12_a_stand_in_cannot_carry_route_conformance(honest):
    mutated = copy.deepcopy(honest)
    mutated["routes"][0]["rows"] = {"state": "measured", "total": 2,
                                    "row_results": {}}
    assert "STANDIN_CLAIMED_AS_ROUTE" in codes(validate.validate_report(mutated))


def test_c12_rows_cannot_be_measured_without_a_head(honest):
    mutated = copy.deepcopy(honest)
    mutated["routes"][0].update({
        "implementation_kind": "merged_product_source",
        "rows": {"state": "measured", "total": 1,
                 "row_results": {"T1.R2": {"state": "conformant",
                                           "evidence": "ev/1"}}}})
    assert "ROWS_WITHOUT_HEAD" in codes(validate.validate_report(mutated))


def test_c12_an_abbreviated_head_is_not_an_identity(honest):
    mutated = copy.deepcopy(honest)
    mutated["routes"][0].update({"implementation_kind": "product_candidate",
                                 "head": "c9073cf"})
    assert "IDENTITY_UNPINNED" in codes(validate.validate_report(mutated))


def test_c12_an_unknown_implementation_kind_is_rejected(honest):
    mutated = copy.deepcopy(honest)
    mutated["routes"][0]["implementation_kind"] = "the_real_thing"
    assert "IMPLEMENTATION_KIND_UNKNOWN" in codes(validate.validate_report(mutated))


# --- helpers ---------------------------------------------------------------

def _skeleton():
    """A minimal valid report around a coverage panel under test."""
    return {
        "schema": 2,
        "run": {"id": "x", "attempt": 1, "started_at": "2026-09-14T00:00:00+00:00",
                "finished_at": "2026-09-14T00:00:00+00:00",
                "outcome": "complete", "exit_code": 0},
        "freshness": {"policy_hours": 36,
                      "measured_at": "2026-09-14T00:00:00+00:00"},
        "harness": {"state": "unavailable", "reason_code": "EVIDENCE_UNBOUND"},
        "ledger": {"state": "unavailable", "reason_code": "EVIDENCE_UNBOUND"},
        "routes": [],
        "identities": {},
    }


def _with_rows(honest, row_results):
    mutated = copy.deepcopy(honest)
    mutated["routes"][0].update({
        "implementation_kind": "product_candidate",
        "head": "c" * 40,
        "rows": {"state": "measured", "total": len(row_results),
                 "row_results": row_results},
    })
    return mutated


def _reload_map(data, tmp=None):
    path = pathlib.Path(tmp or "/tmp") / "capability_map_under_test.json"
    path.write_text(json.dumps(data))
    return classify.load_map(path)


# ── the meta description is DERIVED, not decorative (T10, 2026-09-22) ────────
#
# `site_lint.py` requires a meta description on every document it judges, and a
# page with a <title> is not a fragment, so this page is judged and was failing
# the html gate without one. The risk in satisfying that gate is a FIXED
# sentence: this report's whole point can be "it refused", and a page that
# always describes itself the same way would be the exact lie it exists to
# prevent -- a true label over an unknown result.
#
# So these two rows are the control pair. The first pins what today's artifact
# actually says; the second changes the outcome underneath it and requires the
# sentence to move. A hardcoded description passes the first and fails the
# second, which is the only reason the first is worth anything.

def _description(page):
    import re
    m = re.search(r'<meta name="description" content="([^"]*)"', page)
    return m.group(1) if m else None


def test_the_description_states_todays_real_outcome(honest):
    page = render.render(honest)
    d = _description(page)
    assert d, "no meta description — the html site gate fails on this page"
    assert "REFUSED" in d
    n = honest["coverage"]["ceiling"]["unclassified_count"]
    assert str(n) in d, f"description does not carry the {n} unclassified operations"


def test_the_description_moves_when_the_outcome_does(honest):
    """THE CONTROL. A fixed string passes the row above and fails this one."""
    other = copy.deepcopy(honest)
    other["run"]["outcome"] = "completed"
    moved = _description(render.render(other, findings=[]))
    assert moved != _description(render.render(honest)), \
        "the description did not change when the outcome did — it is not derived"
    assert "REFUSED" not in moved
