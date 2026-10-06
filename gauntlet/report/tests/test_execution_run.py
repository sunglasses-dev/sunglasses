"""The executed partition, the stand in scope sentence and the two ledger lines.

Three groups, each one the same shape as the acceptance controls beside it. The PRODUCER rows
check what `produce.py` does with a run document: no file is exactly the panel it always wrote,
a record that does not bind to tonight's corpus is set aside rather than counted, and the
counts come from the records and nowhere else. The VALIDATOR rows are one mutation per rule,
V1 to V14 and the ledger rules L1 to L7, and each asserts the exact finding code so a rule that
stops firing turns exactly one row red (`guard_sweep.py` renames each code to prove it).

The fixture is built through `produce.build()` against the live pinned corpus, with a run
document of SYNTHETIC records beside it. The records are shaped like the driver's and say
nothing about the product, which is why this file never quotes a number from them.
"""
import copy
import datetime
import json
import pathlib
import sys
import types

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[1] / "boundary"))

import drive                                               # noqa: E402
import produce                                             # noqa: E402
import render                                              # noqa: E402
import schema                                              # noqa: E402
import validate                                            # noqa: E402

OUTCOMES = ["passed", "passed", "passed", "failed", "failed", "refused", "refused"]
LEDGER = {"scope": "cumulative_gate2", "cap": 60, "charges": 36, "unsettled": 0,
          "updated_at": "2026-09-20T10:00:00+00:00"}


def codes(findings):
    return {f.code for f in findings}


def make_record(variant_id, outcome, head):
    held = ["payload_absent_at_destination(client)"]
    record = {
        "record_schema": 1, "variant_id": variant_id, "route": "proxy_strict",
        "implementation_kind": "harness_stand_in", "mode": "head_of_line",
        "harness_head": head, "delivered_digest": "a" * 64, "outcome": outcome, "reason_code": None,
        "control": {"route": "no_mediation", "stimulus_delivered": True},
        "expectation": {"assert_original_payload_absent": True, "bytes_outcome": "withheld"},
        "graded_on": held,
        "assertions": {"held": held, "not_held": [], "no_subject": [], "payload_at_destination": False,
                       "expect_payload_absent": True, "expect_original": None,
                       "declared_frames_delivered_unchanged": None},
        "started_at": "2026-10-05T00:00:00+00:00", "finished_at": "2026-10-05T00:00:01+00:00",
    }
    if outcome == "failed":
        record.update(reason_code="EXEC_CONTRADICTED", graded_on=held,
                      assertions=dict(record["assertions"], held=[], payload_at_destination=True))
    if outcome == "refused":
        record.update(reason_code="EXEC_OBSERVER_ABSENT", graded_on=[],
                      control={"route": "no_mediation", "stimulus_delivered": False},
                      assertions=dict(record["assertions"], held=[]))
    return record


def _now():
    return datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds")


@pytest.fixture(scope="module")
def planned():
    return produce.plan_corpus()


@pytest.fixture(scope="module")
def corpus_digest():
    return produce._digest_tree(produce.MATERIALISED)


@pytest.fixture(scope="module")
def run_doc(planned, corpus_digest):
    head = drive._git_head(drive.REPO)
    ids = sorted(planned["drivable"])[:len(OUTCOMES)]
    records = [make_record(v, o, head) for v, o in zip(ids, OUTCOMES)]
    return drive.build_run_doc(records, started_at=_now(), corpus_digest=corpus_digest,
                               repo=drive.REPO, run_id="fixture")


def _build(tmp_path_factory, doc=None, ledger=LEDGER, raw=None):
    """produce.build() with the imported records pointed at a scratch folder."""
    folder = tmp_path_factory.mktemp("imports")
    run_path, ledger_path = folder / "execution_run.json", folder / "ledger_record.json"
    if raw is not None:
        run_path.write_text(raw)
    elif doc is not None:
        run_path.write_text(json.dumps(doc))
    if ledger is not None:
        ledger_path.write_text(json.dumps(ledger))
    patch = pytest.MonkeyPatch()
    patch.setattr(produce, "EXECUTION_RUN", run_path)
    patch.setattr(produce, "LEDGER_RECORD", ledger_path)
    try:
        return produce.build(run_id="fixture")
    finally:
        patch.undo()


@pytest.fixture(scope="module")
def world(tmp_path_factory, run_doc):
    report, code = _build(tmp_path_factory, run_doc)
    return types.SimpleNamespace(report=report, code=code)


@pytest.fixture(scope="module")
def norun(tmp_path_factory):
    report, code = _build(tmp_path_factory, None, ledger=None)
    return types.SimpleNamespace(report=report, code=code)


def reseal(report):
    """Bring every digest and count back in line after a record was changed, so the rule under
    test is the only one with something to say. Rows for V7, V10 and V11 do NOT call this."""
    run = report["execution_run"]
    header, cov = run["header"], report["coverage"]
    drivable, once = set(cov["drivable_ids"]), set()
    counted = {"passed": 0, "failed": 0, "refused": 0, "errored": 0}
    for record in run["records"]:
        if (record.get("variant_id") in drivable and record["variant_id"] not in once
                and record.get("outcome") in counted):
            once.add(record["variant_id"])
            counted[record["outcome"]] += 1
    header["counts"] = counted
    header["records_digest"] = schema.records_digest(run["records"])
    cov["execution_partition"] = dict(counted, not_run=cov["total"] - sum(counted.values()))
    block = report["routes"][0]["execution"]
    block["records_digest"], block["counts"] = header["records_digest"], dict(header["counts"])
    block["harness_head"] = header["harness_head"]
    for line in report["ledger"].get("lines") or []:
        if line.get("source") == "execution_run":
            line["records_digest"] = header["records_digest"]
    report["identities"]["execution_run_digest"] = schema.canonical_digest(run)
    return report


def mutated(world, change, seal=True):
    report = copy.deepcopy(world.report)
    change(report)
    return reseal(report) if seal else report


def record_of(report, index=0):
    return report["execution_run"]["records"][index]


def passed_record(report):
    return next(r for r in report["execution_run"]["records"] if r["outcome"] == "passed")


# =========================== PRODUCER ===========================================================

def test_the_honest_report_validates_clean(world):
    assert validate.validate_report(world.report) == []


def test_no_run_file_is_exactly_the_panel_it_always_was(norun, planned):
    total = len(planned["drivable"]) + len(planned["blocked"]) + len(planned["invalid"])
    cov = norun.report["coverage"]
    assert cov["execution_partition"] == {"passed": 0, "failed": 0, "refused": 0, "errored": 0,
                                          "not_run": total}
    assert (cov["execution_state"], cov["execution_reason_code"]) == ("not_run", "EXEC_NOT_RUN")
    assert "execution_run" not in norun.report
    assert "execution" not in norun.report["routes"][0]
    assert "execution_run_digest" not in norun.report["identities"]
    assert norun.report["ledger"]["state"] == "unavailable"
    assert validate.validate_report(norun.report) == []


def test_the_counts_come_from_the_records_and_the_rest_stay_not_run(world, planned):
    part = world.report["coverage"]["execution_partition"]
    assert (part["passed"], part["failed"], part["refused"], part["errored"]) == (3, 2, 2, 0)
    assert part["not_run"] == world.report["coverage"]["total"] - len(OUTCOMES)
    assert world.report["coverage"]["execution_state"] == "measured"
    assert world.report["coverage"]["execution_reason_code"] is None


def test_a_record_for_an_undrivable_variant_or_a_repeat_is_not_counted(planned):
    ids = sorted(planned["drivable"])
    doc = {"records": [{"variant_id": ids[0], "outcome": "passed"},
                       {"variant_id": ids[0], "outcome": "passed"},
                       {"variant_id": "G2-99.not_a_variant", "outcome": "passed"},
                       {"variant_id": sorted(planned["blocked"])[0], "outcome": "passed"}]}
    part, state, reason = produce.execution_partition(planned, doc)
    assert part["passed"] == 1 and (state, reason) == ("measured", None)
    assert sum(part.values()) == len(ids) + len(planned["blocked"]) + len(planned["invalid"])


def _set_aside(tmp_path_factory, doc=None, raw=None):
    report, _ = _build(tmp_path_factory, doc, raw=raw)
    cov = report["coverage"]
    assert cov["execution_state"] == "unavailable"
    assert cov["execution_reason_code"] == "EVIDENCE_UNBOUND" and cov["execution_detail"]
    assert cov["execution_partition"]["passed"] == 0 and "execution_run" not in report
    assert validate.validate_report(report) == []
    return cov["execution_detail"]


def test_a_run_made_on_another_corpus_is_set_aside_not_counted(tmp_path_factory, run_doc):
    doc = copy.deepcopy(run_doc)
    doc["header"]["corpus_digest"] = "0" * 64
    assert "corpus" in _set_aside(tmp_path_factory, doc)


def test_a_run_made_with_other_adapter_code_is_set_aside(tmp_path_factory, run_doc):
    doc = copy.deepcopy(run_doc)
    doc["header"]["adapter_digest"] = "0" * 64
    assert "adapter" in _set_aside(tmp_path_factory, doc)


def test_an_old_run_is_set_aside_and_so_is_an_undated_one(tmp_path_factory, run_doc):
    old = copy.deepcopy(run_doc)
    old["header"]["finished_at"] = (datetime.datetime.now(datetime.timezone.utc)
                                    - datetime.timedelta(hours=schema.DEFAULT_FRESHNESS_HOURS + 2)).isoformat()
    assert "freshness" in _set_aside(tmp_path_factory, old)
    undated = copy.deepcopy(run_doc)
    undated["header"]["finished_at"] = "yesterday"
    assert "freshness" in _set_aside(tmp_path_factory, undated)


def test_an_unknown_run_schema_and_an_unreadable_file_are_set_aside(tmp_path_factory, run_doc):
    doc = copy.deepcopy(run_doc)
    doc["header"]["schema"] = 99
    assert "schema" in _set_aside(tmp_path_factory, doc)
    assert "valid JSON" in _set_aside(tmp_path_factory, raw="{not json")
    assert "header" in _set_aside(tmp_path_factory, raw="[]")


def test_the_route_stays_a_stand_in_with_unavailable_rows_and_carries_the_scope_sentence(world):
    route = world.report["routes"][0]
    assert (route["name"], route["implementation_kind"], route["head"]) == (
        "proxy_strict", "harness_stand_in", None)
    assert route["rows"]["state"] == "unavailable"
    assert route["execution"]["fit_scope"] == schema.STANDIN_SCOPE_SENTENCE
    assert route["execution"]["counts"] == world.report["execution_run"]["header"]["counts"]


def test_a_run_does_not_clear_the_refusal(world):
    ceiling = world.report["coverage"]["ceiling"]["state"]
    assert (world.code == 3) == (ceiling == "not_computed")
    assert (world.report["run"]["outcome"] == "refused") == (world.code == 3)


def test_the_ledger_is_two_labelled_lines_built_from_records(world):
    lines = world.report["ledger"]["lines"]
    assert [l["text"] for l in lines] == [
        f"cumulative Gate 2, 36 of 60 {schema.LEDGER_UNIT}", "this nightly, 0 live calls"]
    assert [l["source"] for l in lines] == ["ledger_record", "execution_run"]
    assert world.report["ledger"]["record"] == LEDGER


def test_without_a_ledger_record_the_cumulative_line_says_unavailable_and_carries_no_number(
        tmp_path_factory, run_doc):
    report, _ = _build(tmp_path_factory, run_doc, ledger=None)
    first, second = report["ledger"]["lines"]
    assert first["state"] == "unavailable" and first["text"] is None and "charges" not in first
    assert second["text"] == "this nightly, 0 live calls"
    assert validate.validate_report(report) == []


def test_without_a_run_the_nightly_line_says_unavailable_and_carries_no_number(tmp_path_factory):
    report, _ = _build(tmp_path_factory, None)
    first, second = report["ledger"]["lines"]
    assert first["text"].startswith("cumulative Gate 2") and second["state"] == "unavailable"
    assert second["text"] is None and "charges" not in second
    assert validate.validate_report(report) == []


def test_a_report_with_a_run_in_it_still_renders(world):
    if validate.validate_report(world.report):
        pytest.skip("covered by the clean report row")
    assert "execution_partition.passed" in render.render(world.report)


# =========================== VALIDATOR V1 to V14 ================================================

def test_v1_record_schema(world):
    found = validate.validate_report(mutated(world, lambda r: record_of(r).update(record_schema=2)))
    assert "EXEC_RECORD_SCHEMA" in codes(found)


def test_v1_run_schema(world):
    found = validate.validate_report(mutated(world, lambda r: r["execution_run"]["header"].update(schema=2)))
    assert "EXEC_RECORD_SCHEMA" in codes(found)


def test_v2_record_not_drivable(world):
    found = validate.validate_report(mutated(world, lambda r: record_of(r).update(variant_id="G2-99.fake")))
    assert "EXEC_RECORD_NOT_DRIVABLE" in codes(found)


def test_v2_a_variant_twice(world):
    found = validate.validate_report(mutated(
        world, lambda r: r["execution_run"]["records"].append(copy.deepcopy(record_of(r)))))
    assert "DUPLICATE_IDS" in codes(found)


def test_v3_route_and_kind_on_a_record(world):
    for change in (lambda r: record_of(r).update(route="proxy_default"),
                   lambda r: record_of(r).update(implementation_kind="product_candidate")):
        assert "EXEC_RECORD_KIND" in codes(validate.validate_report(mutated(world, change)))


def test_v3_the_report_route_entry_must_be_the_stand_in(world):
    found = validate.validate_report(mutated(
        world, lambda r: r["routes"][0].update(implementation_kind="product_candidate")))
    assert "EXEC_RECORD_KIND" in codes(found)


def test_v4_outcome_is_an_executed_one(world):
    for outcome in ("not_run", "maybe", None):
        found = validate.validate_report(mutated(world, lambda r, o=outcome: record_of(r).update(outcome=o)))
        assert "EXEC_OUTCOME_UNKNOWN" in codes(found)


def test_v4_a_non_pass_needs_a_reason_in_the_closed_set(world):
    def failed(r):
        return next(x for x in r["execution_run"]["records"] if x["outcome"] == "failed")
    assert "REASON_CODE_MISSING" in codes(validate.validate_report(
        mutated(world, lambda r: failed(r).update(reason_code=None))))
    assert "REASON_CODE_UNKNOWN" in codes(validate.validate_report(
        mutated(world, lambda r: failed(r).update(reason_code="BECAUSE_I_SAID_SO"))))


def test_v5_heads_are_full_commits_and_agree(world):
    assert "IDENTITY_UNPINNED" in codes(validate.validate_report(
        mutated(world, lambda r: record_of(r).update(harness_head="abc1234"))))
    assert "IDENTITY_UNPINNED" in codes(validate.validate_report(
        mutated(world, lambda r: r["execution_run"]["header"].update(engine_head="abc1234"))))
    assert "IDENTITY_UNPINNED" in codes(validate.validate_report(
        mutated(world, lambda r: r["identities"].update(execution_harness_head="0" * 40))))


def test_v6_a_run_on_another_corpus_or_other_code_or_with_no_delivery(world):
    assert "EXEC_RUN_STALE_CORPUS" in codes(validate.validate_report(
        mutated(world, lambda r: r["execution_run"]["header"].update(corpus_digest="0" * 64))))
    assert "EXEC_RUN_STALE_CORPUS" in codes(validate.validate_report(
        mutated(world, lambda r: passed_record(r).update(delivered_digest=""))))
    assert "EXEC_RUN_STALE_CODE" in codes(validate.validate_report(
        mutated(world, lambda r: r["execution_run"]["header"].update(adapter_digest="0" * 64))))


def test_v7_header_counts_recompute_from_the_records(world):
    found = validate.validate_report(mutated(
        world, lambda r: r["execution_run"]["header"]["counts"].update(passed=29), seal=False))
    assert any(f.code == "AGGREGATE_MISMATCH" and f.path == "execution_run.header.counts" for f in found)


def test_v7_the_report_partition_recomputes_from_the_records(world):
    def inflate(report):
        report["coverage"]["execution_partition"]["passed"] += 1
        report["coverage"]["execution_partition"]["not_run"] -= 1
    found = validate.validate_report(mutated(world, inflate, seal=False))
    assert any(f.code == "AGGREGATE_MISMATCH" and f.path == "coverage.execution_partition.passed"
               for f in found)


def test_v8_passed_needs_a_proven_stimulus(world):
    found = validate.validate_report(mutated(
        world, lambda r: passed_record(r)["control"].update(stimulus_delivered=False)))
    assert "PASSED_WITHOUT_STIMULUS_PROOF" in codes(found)


def test_v8_passed_needs_a_subject(world):
    assert "PASSED_WITHOUT_SUBJECT" in codes(validate.validate_report(
        mutated(world, lambda r: passed_record(r).update(graded_on=[]))))
    assert "PASSED_WITHOUT_SUBJECT" in codes(validate.validate_report(
        mutated(world, lambda r: passed_record(r)["assertions"].update(held=[]))))


def test_v8_passed_cannot_be_contradicted_by_its_own_evidence(world):
    for change in (lambda r: passed_record(r)["assertions"].update(payload_at_destination=True),
                   lambda r: passed_record(r)["assertions"].update(payload_at_destination=None),
                   lambda r: passed_record(r)["assertions"].update(not_held=["x"]),
                   lambda r: passed_record(r)["assertions"].update(
                       expect_original=True, declared_frames_delivered_unchanged=False)):
        assert "PASSED_CONTRADICTED" in codes(validate.validate_report(mutated(world, change)))


def test_v9_an_unproven_stimulus_is_never_counted_as_passed_or_failed(world):
    def failed(r):
        return next(x for x in r["execution_run"]["records"] if x["outcome"] == "failed")
    assert "EXEC_UNPROVEN_COUNTED" in codes(validate.validate_report(
        mutated(world, lambda r: failed(r)["control"].update(stimulus_delivered=False))))
    assert "EXEC_UNPROVEN_COUNTED" in codes(validate.validate_report(
        mutated(world, lambda r: passed_record(r).pop("control"))))


def test_v10_the_records_digest_recomputes(world):
    found = validate.validate_report(mutated(
        world, lambda r: record_of(r).update(cause="edited after the digest"), seal=False))
    assert "EXEC_RECORDS_DIGEST" in codes(found)


def test_v11_the_run_digest_in_identities_is_the_embedded_documents(world):
    found = validate.validate_report(mutated(
        world, lambda r: r["identities"].update(execution_run_digest="0" * 64), seal=False))
    assert "EXEC_RUN_DIGEST" in codes(found)


def test_v12_measured_needs_a_run_beneath_it(world, norun):
    assert "EXEC_STATE_UNBACKED" in codes(validate.validate_report(
        mutated(world, lambda r: r.pop("execution_run"), seal=False)))
    unbacked = copy.deepcopy(norun.report)
    unbacked["coverage"]["execution_state"] = "measured"
    assert "EXEC_STATE_UNBACKED" in codes(validate.validate_report(unbacked))


def test_v12_a_run_needs_a_measured_state_above_it(world):
    assert "EXEC_STATE_UNBACKED" in codes(validate.validate_report(
        mutated(world, lambda r: r["coverage"].update(execution_state="not_run"), seal=False)))


def test_v12_not_run_cannot_carry_executed_numbers(norun):
    report = copy.deepcopy(norun.report)
    report["coverage"]["execution_partition"]["passed"] = 1
    report["coverage"]["execution_partition"]["not_run"] -= 1
    assert "EXEC_STATE_UNBACKED" in codes(validate.validate_report(report))


def test_v13_an_old_or_undated_run_is_stale(world):
    old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        hours=schema.DEFAULT_FRESHNESS_HOURS + 5)).isoformat()
    for value in (old, "yesterday", None):
        found = validate.validate_report(mutated(
            world, lambda r, v=value: r["execution_run"]["header"].update(finished_at=v)))
        assert "EXEC_RUN_STALE" in codes(found)


def test_v14_no_route_rows_on_a_record_or_beside_the_route(world):
    assert "STANDIN_CLAIMED_AS_ROUTE" in codes(validate.validate_report(
        mutated(world, lambda r: record_of(r).update(rows={"state": "measured"}))))
    assert "STANDIN_CLAIMED_AS_ROUTE" in codes(validate.validate_report(
        mutated(world, lambda r: r["routes"][0]["execution"].update(row_results={"x": 1}))))


def test_v14_the_old_guard_still_fires_on_a_stand_in_with_numeric_rows(world):
    found = validate.validate_report(mutated(
        world, lambda r: r["routes"][0].update(rows={"state": "measured", "row_results": {}})))
    assert "STANDIN_CLAIMED_AS_ROUTE" in codes(found)


def test_v14_the_route_carries_the_sentence_that_limits_the_examiners_finding(world):
    found = validate.validate_report(mutated(
        world, lambda r: r["routes"][0]["execution"].update(fit_scope="FIT")))
    assert "STANDIN_SCOPE_MISSING" in codes(found)
    found = validate.validate_report(mutated(
        world, lambda r: r["routes"][0]["execution"].pop("fit_scope")))
    assert "STANDIN_SCOPE_MISSING" in codes(found)


def test_v14_the_route_block_equals_the_header_it_summarises(world):
    # The block is its own copy. If it shared the header's dict, editing one would edit the other
    # and this row could never fail.
    assert (world.report["routes"][0]["execution"]["counts"]
            is not world.report["execution_run"]["header"]["counts"])
    found = validate.validate_report(mutated(
        world, lambda r: r["routes"][0]["execution"]["counts"].update(passed=29), seal=False))
    assert any(f.code == "AGGREGATE_MISMATCH" and f.path == "routes[proxy_strict].execution" for f in found)


# =========================== LEDGER L1 to L7 ====================================================

def line_of(report, scope):
    return next(l for l in report["ledger"]["lines"] if l.get("scope") == scope)


def retext(line):
    line["text"] = schema.ledger_line_text(line)


CUM, NIGHT = "cumulative_gate2", "no_live_calls_standin_run"


def test_l1_unit(world):
    found = validate.validate_report(mutated(world, lambda r: r["ledger"].update(unit="dollars")))
    assert "LEDGER_UNIT_WRONG" in codes(found)


def test_l2_scope_is_in_the_closed_set(world):
    def change(report):
        line = line_of(report, CUM)
        line["scope"] = "weekly"
        retext(line)
    assert "LEDGER_SCOPE_UNKNOWN" in codes(validate.validate_report(mutated(world, change)))


def test_l3_counts_are_non_negative_whole_numbers_and_charges_do_not_exceed_the_cap(world):
    for field, value in (("charges", -1), ("charges", 61), ("cap", "60"), ("unsettled", None),
                         ("charges", True), ("charges", 1.5)):
        def change(report, f=field, v=value):
            line = line_of(report, CUM)
            line[f] = v
            report["ledger"]["record"][f] = v
            retext(line)
        assert "LEDGER_COUNT_INVALID" in codes(validate.validate_report(mutated(world, change))), (field, value)


def test_l3_an_unavailable_line_carries_no_count_and_has_a_reason(world):
    def change(report):
        line = line_of(report, CUM)
        report["ledger"]["lines"][0] = {"scope": CUM, "state": "unavailable",
                                        "reason_code": "EVIDENCE_UNBOUND", "source": "ledger_record",
                                        "charges": 36, "text": None}
    assert "LEDGER_COUNT_INVALID" in codes(validate.validate_report(mutated(world, change)))

    def no_reason(report):
        report["ledger"]["lines"][0] = {"scope": CUM, "state": "unavailable", "source": "ledger_record",
                                        "text": None}
    assert "REASON_CODE_MISSING" in codes(validate.validate_report(mutated(world, no_reason)))


def test_l4_a_line_is_dated_and_not_from_the_future(world):
    for value in (None, "last week", "2999-01-01T00:00:00+00:00"):
        def change(report, v=value):
            line_of(report, CUM)["updated_at"] = v
            report["ledger"]["record"]["updated_at"] = v
        assert "LEDGER_UNDATED" in codes(validate.validate_report(mutated(world, change)))


def test_l5_the_cumulative_line_is_the_imported_record(world):
    assert "LEDGER_NOT_IMPORTED" in codes(validate.validate_report(
        mutated(world, lambda r: line_of(r, CUM).update(record_digest="0" * 64))))
    assert "LEDGER_NOT_IMPORTED" in codes(validate.validate_report(
        mutated(world, lambda r: r["ledger"].pop("record"))))

    def retyped(report):
        line = line_of(report, CUM)
        line["charges"] = 35
        retext(line)
    assert "LEDGER_NOT_IMPORTED" in codes(validate.validate_report(mutated(world, retyped)))


def test_l5_the_nightly_line_is_the_run_documents_ledger_block(world):
    assert "LEDGER_NOT_IMPORTED" in codes(validate.validate_report(
        mutated(world, lambda r: line_of(r, NIGHT).update(records_digest="0" * 64), seal=False)))
    assert "LEDGER_NOT_IMPORTED" in codes(validate.validate_report(
        mutated(world, lambda r: line_of(r, NIGHT).update(source="typed"))))


def test_l6_a_zero_is_readable_only_where_the_scope_says_why(world):
    def change(report):
        line = line_of(report, CUM)
        line["charges"] = 0
        report["ledger"]["record"]["charges"] = 0
        retext(line)
    assert "LEDGER_ZERO_UNSCOPED" in codes(validate.validate_report(mutated(world, change)))


def test_l7_a_stand_in_run_has_no_live_batch_and_no_live_calls(world):
    def batch(report):
        line = line_of(report, NIGHT)
        line["scope"] = "live_driver_batch"
        line["cap"] = line["unsettled"] = 0
        line["charges"] = 0
        retext(line)
    assert "LEDGER_SCOPE_CONTRADICTED" in codes(validate.validate_report(mutated(world, batch)))

    def calls(report):
        line = line_of(report, NIGHT)
        line["charges"] = 3
        report["execution_run"]["header"]["ledger"]["charges"] = 3
        retext(line)
    assert "LEDGER_SCOPE_CONTRADICTED" in codes(validate.validate_report(mutated(world, calls)))


def test_the_two_lines_are_shown_together(world):
    one = validate.validate_report(mutated(world, lambda r: r["ledger"]["lines"].pop()))
    two = validate.validate_report(mutated(world, lambda r: r["ledger"].update(lines=[])))
    assert "LEDGER_LINES_MISSING" in codes(one) and "LEDGER_LINES_MISSING" in codes(two)
    assert "LEDGER_LINES_MISSING" in codes(validate.validate_report(
        mutated(world, lambda r: r["ledger"].pop("lines"))))


def test_a_line_whose_words_were_typed_is_refused(world):
    found = validate.validate_report(mutated(
        world, lambda r: line_of(r, CUM).update(text="cumulative Gate 2, 34 of 60")))
    assert "LEDGER_LINE_TYPED" in codes(found)
