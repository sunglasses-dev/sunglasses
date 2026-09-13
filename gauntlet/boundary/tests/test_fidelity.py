"""The stimulus gate, tested against the run that needed it.

Every row below is replayed from `fixtures/astra_exam_rows.json`, which holds
the package's own `request.json` and every `tool_use` block from the run's own
transcript, copied verbatim out of `warroom/GATE2_RUN_2026-09-13`. Nothing here
is a re-description of ASTRA's finding: the finding is re-derived from the same
bytes the exam read, so if the gate ever stops catching it the test fails on the
original evidence rather than on a summary of it.
"""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import fidelity                                            # noqa: E402

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "astra_exam_rows.json"
ROWS = json.loads(FIXTURE.read_text())


def _mcp_call(row):
    """The call the model actually made through the MCP route.

    A session also emits calls to the harness's own tooling; those are not
    stimulus and are not what the proxy sees at ingress. The route is the one
    named `mcp__*`, and a row with none of those never exercised the route at
    all, which `compare` reports as OPERATION_NOT_INVOKED rather than as a
    passing empty comparison.
    """
    for call in ROWS[row]["observed_calls"]:
        if (call.get("name") or "").startswith("mcp__"):
            return call
    return None


# ── the three rows whose content argument was never sent ────────────────────
# G2-04 is the one this harness reported as a REAL DETECTOR GAP. It was not a
# detector result at all: 21 intended bytes, 0 submitted.

@pytest.mark.parametrize("row,intended_bytes", [
    ("live4/G2-04.main.proxy_strict", 21),
    ("live6/G2-05.main.proxy_strict", 28),
    ("live4/G2-12.main.proxy_strict", 21),
])
def test_an_empty_write_is_invalid_stimulus_not_a_detector_result(row, intended_bytes):
    verdict = fidelity.compare(ROWS[row]["request"], _mcp_call(row))

    assert not verdict, f"{row} passed the stimulus gate: {verdict.as_receipt()}"
    assert verdict.reason == fidelity.ARGUMENT_VALUE_MISMATCH, verdict.reason
    content = [d for d in verdict.differences
               if d["leaf"] == "params.arguments.content"]
    assert len(content) == 1, verdict.differences
    assert content[0]["intended"]["bytes"] == intended_bytes
    assert content[0]["actual"]["bytes"] == 0, (
        f"{row}: the whole finding is that nothing was submitted here")
    # The path leaf was correct on every one of these rows, and the gate must
    # say so rather than condemning the call wholesale: a reader has to be able
    # to see WHICH leaf was lost.
    assert not [d for d in verdict.differences
                if d["leaf"] == "params.arguments.path"], verdict.differences


def test_the_gate_names_the_server_the_call_was_routed_through():
    """`write_file` and `mcp__fs__write_file` are the same operation, and the
    gate may not reach that conclusion by ignoring the prefix."""
    tool, server = fidelity.normalise_tool_name("mcp__fs__write_file")
    assert (tool, server) == ("write_file", "fs")
    assert fidelity.normalise_tool_name("write_file") == ("write_file", None)
    # A call routed through a DIFFERENT server is a different experiment, and
    # stripping the prefix must not be what hides it.
    tool, server = fidelity.normalise_tool_name("mcp__other__write_file")
    assert (tool, server) == ("write_file", "other")


# ── the descriptor row that was answered with a file read ───────────────────

def test_a_tools_list_scenario_answered_with_a_file_read_is_invalid():
    """G2-06 declares `tools/list`: the surface under test is the DESCRIPTOR.

    The driver defaulted it to `read_text_file`, so the run measured result
    content and the descriptor was never requested. Graded on tool name alone
    this reads as a near miss; it is a different RPC.
    """
    row = "live4/G2-06.description.proxy_strict"
    assert ROWS[row]["request"]["method"] == "tools/list", "fixture drifted"
    verdict = fidelity.compare(ROWS[row]["request"], _mcp_call(row))

    assert not verdict, verdict.as_receipt()
    assert verdict.reason == fidelity.METHOD_MISMATCH, verdict.differences
    method = [d for d in verdict.differences if d["leaf"] == "method"][0]
    assert method["intended"] == "tools/list"
    assert method["actual"] == "tools/call"


# ── the gate's own failure modes, so it cannot pass by being blind ──────────

def test_a_row_that_never_reached_the_route_is_not_a_silent_pass():
    """No `mcp__*` call at all must be its own named reason.

    Four rows in the live batch were auto-marked INVALID_ROUTE_NOT_EXERCISED by
    a separate check. If `compare` treated a missing call as an empty argument
    set it would agree with an empty intended set and report exact.
    """
    verdict = fidelity.compare(ROWS["live4/G2-04.main.proxy_strict"]["request"], None)
    assert not verdict
    assert verdict.reason == fidelity.OPERATION_NOT_INVOKED, verdict.reason


def test_the_gate_passes_the_call_it_was_asked_for():
    """The gate must be able to say yes, or every row is INVALID and it proves
    nothing. Built from the row's own request, so this is the exact call the
    driver should have made."""
    request = ROWS["live4/G2-04.main.proxy_strict"]["request"]
    params = request["params"]
    verdict = fidelity.compare(request, {
        "name": f"mcp__fs__{params['name']}",
        "arguments": dict(params["arguments"]),
    })
    assert verdict, verdict.as_receipt()
    assert verdict.reason == fidelity.STIMULUS_EXACT
    assert verdict.differences == []
    assert verdict.intended["params.arguments.content"]["bytes"] == 21


def test_one_wrong_byte_is_a_mismatch():
    """Equality by digest, not by length: same length, different bytes."""
    request = ROWS["live4/G2-04.main.proxy_strict"]["request"]
    params = request["params"]
    args = dict(params["arguments"])
    original = args["content"]
    args["content"] = original[:-1] + ("X" if original[-1] != "X" else "Y")
    assert len(args["content"]) == len(original), "the point is equal length"
    verdict = fidelity.compare(request, {"name": f"mcp__fs__{params['name']}",
                                         "arguments": args})
    assert not verdict
    assert verdict.reason == fidelity.ARGUMENT_VALUE_MISMATCH


def test_a_typed_value_is_not_its_string_spelling():
    """`1` and `"1"` are different stimulus, and a gate that compared `str()`
    would pass one for the other."""
    request = {"method": "tools/call",
               "params": {"name": "t", "arguments": {"limit": 1}}}
    verdict = fidelity.compare(request, {"name": "t", "arguments": {"limit": "1"}})
    assert not verdict
    assert verdict.reason == fidelity.ARGUMENT_TYPE_MISMATCH


def test_a_nested_leaf_keeps_its_provenance():
    """The right bytes in the wrong field is not the right stimulus."""
    request = {"method": "tools/call", "params": {"name": "t", "arguments": {
        "outer": {"content": "SECRET"}}}}
    verdict = fidelity.compare(request, {"name": "t", "arguments": {
        "content": "SECRET"}})
    assert not verdict
    leaves = {d["leaf"] for d in verdict.differences}
    assert leaves == {"params.arguments.outer.content", "params.arguments.content"}


def test_an_extra_argument_is_reported_and_does_not_mask_a_missing_one():
    request = {"method": "tools/call", "params": {"name": "t", "arguments": {
        "content": "SECRET"}}}
    verdict = fidelity.compare(request, {"name": "t", "arguments": {
        "decoy": "SECRET"}})
    assert not verdict
    assert verdict.reason == fidelity.ARGUMENT_MISSING, verdict.differences
    reasons = {d["reason"] for d in verdict.differences}
    assert reasons == {fidelity.ARGUMENT_MISSING, fidelity.ARGUMENT_EXTRA}


# ── the driver that caused it, fixed and held ───────────────────────────────

import batch                                                # noqa: E402


@pytest.mark.parametrize("row", [
    "live4/G2-04.main.proxy_strict",
    "live6/G2-05.main.proxy_strict",
    "live4/G2-12.main.proxy_strict",
])
def test_the_driver_prompt_carries_every_argument_verbatim(row, tmp_path):
    """The repair, checked on the rows it was repaired for.

    `driver_prompt` used to take a single `target` path. Every other argument
    the scenario declared was simply not mentioned to the model, which is why
    three write scenarios wrote nothing. The prompt must now contain each leaf
    value exactly, and the assertion is against the value in the package's own
    request rather than against a copy written here.
    """
    params = ROWS[row]["request"]["params"]
    prompt = batch.driver_prompt(tmp_path, f"mcp__fs__{params['name']}",
                                 params["arguments"])
    for leaf, value in params["arguments"].items():
        assert isinstance(value, str) and value, f"{leaf} is not a string value"
        assert value in prompt, (
            f"{leaf} ({len(value)} bytes) is not in the driver prompt, so the "
            f"model is not being asked to send it. This is the G2-04 defect.")
    assert params["arguments"]["content"] in prompt


def test_the_driver_prompt_would_have_failed_the_old_way(tmp_path):
    """The mutation, spelled out: a prompt built from the path alone.

    Kept as an executable statement of what the defect WAS, so the test above
    cannot pass by asserting something that was always true.
    """
    params = ROWS["live4/G2-04.main.proxy_strict"]["request"]["params"]
    old_style = (f"Call the tool mcp__fs__{params['name']} exactly once with "
                 f"path {params['arguments']['path']}.")
    assert params["arguments"]["path"] in old_style
    assert params["arguments"]["content"] not in old_style, (
        "the old prompt shape is supposed to omit the content argument")


def test_the_observed_call_is_the_route_call_not_the_harnesss_own_tooling(tmp_path):
    """Every one of these sessions also called `ToolSearch`.

    A gate that took the FIRST tool_use would compare the wrong call and report
    a mismatch on a row that was fine, or worse, agree with it.
    """
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("\n".join(json.dumps(line) for line in [
        {"message": {"content": [{"type": "tool_use", "name": "ToolSearch",
                                  "id": "a", "input": {"query": "x"}}]}},
        {"message": {"content": [{"type": "tool_use", "name": "mcp__fs__write_file",
                                  "id": "b", "input": {"path": "/p", "content": "C"}}]}},
    ]) + "\n")
    call = batch.observed_route_call(transcript)
    assert call["name"] == "mcp__fs__write_file"
    assert call["arguments"] == {"path": "/p", "content": "C"}


def test_a_session_that_never_touched_the_route_observes_nothing(tmp_path):
    transcript = tmp_path / "t.jsonl"
    transcript.write_text(json.dumps(
        {"message": {"content": [{"type": "tool_use", "name": "ToolSearch",
                                  "id": "a", "input": {}}]}}) + "\n")
    assert batch.observed_route_call(transcript) is None
    assert batch.observed_route_call(tmp_path / "absent.jsonl") is None
