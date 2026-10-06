"""Row 14. The seven coverage gaps ASTRA found in rows 12 and 13 (r1, 005a88737c63).

Each test below was written first and run against 4549215d, where it is RED, then the fix was
made and it is GREEN. They are named for the finding they close, R1 to R7, so a failure says
which one came back. The existing 206 rows all passed on 4549215d: these were gaps in what the
rows covered, not rows that failed.

R1 an execution block with no run, or on a second route, was never validated.
R2 an unavailable execution state allowed executed counts.
R3 an unavailable ledger line could carry text, and the page printed it.
R4 L5 compared two digest labels and never recomputed the digest from the record.
R5 V5 did not pin the engine head and V13 let a run finish in the future.
R6 transcription decoded entities for any element, so a count could hide in a script element.
R7 one malformed record made the producer raise instead of writing a refusal report.

Fixtures come from `test_execution_run.py` and the records are synthetic.
"""
import copy
import datetime
import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import drive                                                # noqa: E402
import produce                                              # noqa: E402
import render                                               # noqa: E402
import schema                                               # noqa: E402
import validate                                             # noqa: E402
from test_execution_run import (                            # noqa: E402,F401
    LEDGER, _build, codes, corpus_digest, line_of, norun, planned, retext, run_doc, world)

CUM = "cumulative_gate2"
PASSED_SPAN = '<span class="fig" data-bound="coverage.execution_partition.passed">'


def at(findings, prefix):
    return {f.code for f in findings if f.path.startswith(prefix)}


def refused(report):
    findings = validate.validate_report(report)
    assert findings
    with pytest.raises(render.WillNotRender):
        render.render(report)
    return findings


def block_with(**changes):
    block = {"state": "measured", "records_digest": "a" * 64, "harness_head": "b" * 40,
             "counts": {"passed": 999, "failed": 0, "refused": 0, "errored": 0},
             "fit_scope": schema.STANDIN_SCOPE_SENTENCE}
    block.update(changes)
    return block


# ---------------------------------------------------------------------------------------- R1
def test_r1_a_block_with_no_run_beneath_it_is_refused(norun):
    report = copy.deepcopy(norun.report)
    assert validate.validate_report(report) == []
    report["routes"][0]["execution"] = block_with(
        fit_scope="The examiner confirmed these variants against the product.")
    findings = refused(report)
    assert "EXEC_STATE_UNBACKED" in at(findings, "routes[0].execution")


def test_r1_the_renderer_draws_no_block_without_a_run(norun):
    report = copy.deepcopy(norun.report)
    report["routes"][0]["execution"] = block_with()
    page = render.render(report, findings=[])            # the renderer alone, past the validator
    assert "What ran on this route" not in page and "999" not in page.replace(
        report["identities"]["corpus_digest"], "")


def test_r1_a_second_route_block_is_validated_like_the_first(world):
    report = copy.deepcopy(world.report)
    second = copy.deepcopy(report["routes"][0])
    second["name"] = "another_route"
    second["execution"]["fit_scope"] = "These variants passed against the product."
    report["routes"].append(second)
    findings = refused(report)
    assert "STANDIN_SCOPE_MISSING" in at(findings, "routes[1].execution")


def test_r1_a_second_route_block_that_disagrees_with_the_run_is_refused(world):
    report = copy.deepcopy(world.report)
    second = copy.deepcopy(report["routes"][0])
    second["name"] = "another_route"
    second["execution"]["counts"]["passed"] = 999
    report["routes"].append(second)
    findings = refused(report)
    assert "AGGREGATE_MISMATCH" in at(findings, "routes[1].execution")


# ---------------------------------------------------------------------------------------- R2
@pytest.mark.parametrize("state", ["unavailable", "not_run", "weird", None])
def test_r2_executed_counts_need_a_measured_state_and_a_run(norun, state):
    report = copy.deepcopy(norun.report)
    cov = report["coverage"]
    if state is None:
        del cov["execution_state"]
    else:
        cov["execution_state"] = state
    cov["execution_partition"]["passed"] = 1
    cov["execution_partition"]["not_run"] -= 1
    findings = refused(report)
    assert "EXEC_STATE_UNBACKED" in at(findings, "coverage.execution_partition")


# ---------------------------------------------------------------------------------------- R3
def unavailable_cumulative(report, **extra):
    line = line_of(report, CUM)
    for key in ("cap", "charges", "unsettled", "record_digest", "updated_at"):
        line.pop(key, None)
    line.update(state="unavailable", reason_code="EVIDENCE_UNBOUND",
                text="cumulative Gate 2, 999 of 999 charged driver invocations")
    line.update(extra)
    return line


def test_r3_an_unavailable_line_carries_no_text(world):
    report = copy.deepcopy(world.report)
    unavailable_cumulative(report)
    findings = refused(report)
    assert "LEDGER_LINE_TYPED" in at(findings, "ledger.lines[0]")


def test_r3_an_unavailable_line_carries_no_date_or_digest(world):
    report = copy.deepcopy(world.report)
    unavailable_cumulative(report, text=None, updated_at="2026-09-20T10:00:00+00:00")
    findings = refused(report)
    assert "LEDGER_COUNT_INVALID" in at(findings, "ledger.lines[0]")


def test_r3_lines_under_a_panel_that_is_not_numeric_are_refused(world):
    report = copy.deepcopy(world.report)
    report["ledger"]["state"] = "unavailable"
    report["ledger"]["reason_code"] = "EVIDENCE_UNBOUND"
    findings = refused(report)
    assert "ledger.lines" in {f.path for f in findings}


def test_r3_the_renderer_obeys_the_state_not_the_presence_of_text(world):
    report = copy.deepcopy(world.report)
    unavailable_cumulative(report)
    page = render.render(report, findings=[])            # the renderer alone, past the validator
    assert "999 of 999" not in page


def test_r3_the_renderer_draws_no_lines_under_a_panel_that_is_not_numeric(world):
    report = copy.deepcopy(world.report)
    report["ledger"]["state"] = "unavailable"
    report["ledger"]["reason_code"] = "EVIDENCE_UNBOUND"
    page = render.render(report, findings=[])
    assert 'class="ledger-lines"' not in page and "cumulative Gate 2" not in page


# ---------------------------------------------------------------------------------------- R4
def test_r4_the_ledger_digest_is_the_canonical_digest_of_the_record(world):
    panel = world.report["ledger"]
    assert panel["record_digest"] == schema.canonical_digest(panel["record"])


def test_r4_a_record_and_line_edited_together_under_the_old_digest_is_refused(world):
    report = copy.deepcopy(world.report)
    report["ledger"]["record"]["charges"] = 35
    line = line_of(report, CUM)
    line["charges"] = 35
    retext(line)
    findings = refused(report)
    assert "LEDGER_NOT_IMPORTED" in at(findings, "ledger")


def test_r4_the_date_and_unsettled_count_are_compared_not_only_scope_cap_and_charges(world):
    for field, value in (("unsettled", 5), ("updated_at", "2026-09-19T10:00:00+00:00")):
        report = copy.deepcopy(world.report)
        report["ledger"]["record"][field] = value
        report["ledger"]["record_digest"] = schema.canonical_digest(report["ledger"]["record"])
        line_of(report, CUM)["record_digest"] = report["ledger"]["record_digest"]
        assert "LEDGER_NOT_IMPORTED" in codes(validate.validate_report(report)), field


# ---------------------------------------------------------------------------------------- R5
def reseal_run_digest(report):
    report["identities"]["execution_run_digest"] = schema.canonical_digest(report["execution_run"])


def test_r5_the_report_pins_the_engine_head(world):
    assert world.report["identities"]["engine_head"] == drive._git_head(drive.REPO)


def test_r5_a_run_made_on_another_engine_head_is_refused(world):
    report = copy.deepcopy(world.report)
    report["execution_run"]["header"]["engine_head"] = "c" * 40
    reseal_run_digest(report)
    findings = validate.validate_report(report)
    assert "IDENTITY_UNPINNED" in at(findings, "execution_run.header.engine_head")


def test_r5_a_run_made_on_another_engine_head_is_set_aside_by_the_producer(world, corpus_digest):
    doc = copy.deepcopy(world.report["execution_run"])
    doc["header"]["engine_head"] = "c" * 40
    started = world.report["freshness"]["measured_at"]
    assert produce.usable_run(doc, corpus_digest, started)[0] is None


def test_r5_a_run_that_finished_in_the_future_is_refused(world):
    report = copy.deepcopy(world.report)
    report["execution_run"]["header"]["finished_at"] = "2099-01-01T00:00:00+00:00"
    reseal_run_digest(report)
    findings = validate.validate_report(report)
    assert "EXEC_RUN_STALE" in at(findings, "execution_run.header.finished_at")


def test_r5_a_run_that_finished_after_the_measurement_is_refused(world):
    report = copy.deepcopy(world.report)
    measured = datetime.datetime.fromisoformat(report["freshness"]["measured_at"])
    report["execution_run"]["header"]["finished_at"] = (
        measured + datetime.timedelta(minutes=5)).isoformat(timespec="seconds")
    reseal_run_digest(report)
    assert "EXEC_RUN_STALE" in codes(validate.validate_report(report))


def test_r5_the_producer_sets_aside_a_run_that_finished_in_the_future(world, corpus_digest):
    doc = copy.deepcopy(world.report["execution_run"])
    doc["header"]["finished_at"] = "2099-01-01T00:00:00+00:00"
    started = world.report["freshness"]["measured_at"]
    assert produce.usable_run(doc, corpus_digest, started)[0] is None


# ---------------------------------------------------------------------------------------- R6
@pytest.fixture(scope="module")
def page(world):
    return render.render(world.report)


def passed_span(page, world):
    value = world.report["coverage"]["execution_partition"]["passed"]
    span = f"{PASSED_SPAN}{value}</span>"
    assert span in page
    return span, value


def test_r6_a_count_hidden_in_a_script_element_is_refused(world, page):
    span, value = passed_span(page, world)
    hidden = ('<script data-bound="coverage.execution_partition.passed">'
              + "".join(f"&#{ord(c)};" for c in str(value)) + "</script>")
    found = validate.check_transcription(page.replace(span, hidden), world.report)
    assert "BINDING_NOT_VISIBLE" in codes(found)


@pytest.mark.parametrize("tag", ["style", "template", "title", "textarea"])
def test_r6_a_binding_on_a_non_visible_element_is_refused(world, page, tag):
    span, value = passed_span(page, world)
    swapped = f'<{tag} data-bound="coverage.execution_partition.passed">{value}</{tag}>'
    found = validate.check_transcription(page.replace(span, swapped), world.report)
    assert "BINDING_NOT_VISIBLE" in codes(found)


def test_r6_a_hidden_bound_element_is_refused(world, page):
    span, value = passed_span(page, world)
    swapped = span.replace("<span ", "<span hidden ")
    found = validate.check_transcription(page.replace(span, swapped), world.report)
    assert "BINDING_NOT_VISIBLE" in codes(found)


def test_r6_the_text_of_a_bound_element_is_all_of_its_text():
    html = '<span data-bound="a">3<b>4</b></span>'
    assert "TRANSCRIPTION_MISMATCH" in codes(validate.check_transcription(html, {"a": 3}))
    assert validate.check_transcription(html, {"a": 34}) == []


def test_r6_a_visible_encoded_count_is_still_what_a_browser_shows(world, page):
    span, value = passed_span(page, world)
    encoded = span.replace(f">{value}<", f">&#{ord(str(value)[0])};<") if len(str(value)) == 1 else span
    assert validate.check_transcription(page.replace(span, encoded), world.report) == []


def test_r6_a_ledger_line_that_lost_its_binding_is_refused(world, page):
    text = world.report["ledger"]["lines"][0]["text"]
    bound = f'<span class="bound-text" data-bound="ledger.lines[0].text">{text}</span>'
    assert bound in page
    found = validate.check_transcription(page.replace(bound, f"<span>{text}</span>"), world.report)
    assert "BINDING_MISSING" in codes(found)


def test_r6_a_scope_sentence_that_lost_its_binding_is_refused(world, page):
    sentence = schema.STANDIN_SCOPE_SENTENCE.replace("'", "&#x27;")
    bound = f'<span class="bound-text" data-bound="routes[0].execution.fit_scope">{sentence}</span>'
    assert bound in page
    found = validate.check_transcription(page.replace(bound, f"<span>{sentence}</span>"),
                                         world.report)
    assert "BINDING_MISSING" in codes(found)


# ---------------------------------------------------------------------------------------- R7
def run_with_bad_records(run_doc, bad):
    doc = copy.deepcopy(run_doc)
    doc["records"] = [bad] + doc["records"]
    return doc


@pytest.mark.parametrize("bad", [None, 7, "text", [], {"outcome": "passed"},
                                 {"variant_id": ["x"], "outcome": "passed"},
                                 {"variant_id": "x", "outcome": {"y": 1}}])
def test_r7_a_malformed_record_is_a_refusal_report_not_a_raise(tmp_path_factory, run_doc, bad):
    report, code = _build(tmp_path_factory, run_with_bad_records(run_doc, bad))
    assert code == 3
    assert report["run"]["outcome"] == "refused" and report["run"]["reason_code"] == "RUN_REFUSED"
    assert report["coverage"]["execution_state"] == "unavailable"
    assert "execution_run" not in report
    assert validate.validate_report(report) == []


def test_r7_the_partition_counter_skips_what_it_cannot_read(planned, run_doc):
    doc = run_with_bad_records(run_doc, None)
    part, state, _ = produce.execution_partition(planned, doc)
    assert state == "measured" and sum(part.values()) > 0


def test_r7_a_run_file_that_is_not_json_is_still_a_refusal_report(tmp_path_factory):
    report, code = _build(tmp_path_factory, None, raw="{ not json")
    assert code == 3 and report["run"]["reason_code"] == "RUN_REFUSED"
