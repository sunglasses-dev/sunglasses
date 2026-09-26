"""The client's tests. It never calls a model here; that is the point of one of them."""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from client.observe import (                                   # noqa: E402
    InstrumentedClient, Mode, SpendNotAuthorised, extract_tool_result,
)


def _transcript(tmp_path, blocks):
    lines = [json.dumps({"type": "assistant", "message": {"content": blocks}})]
    path = tmp_path / "t.jsonl"
    path.write_text("\n".join(lines) + "\n")
    return path


# ── spending is not this code's decision ───────────────────────────────────

def test_an_observed_client_refuses_to_exist_without_an_explicit_budget(tmp_path):
    """A live run spends real usage. The refusal is at construction."""
    with pytest.raises(SpendNotAuthorised) as refused:
        InstrumentedClient(tmp_path, mode=Mode.OBSERVED)
    assert "budget" in str(refused.value)


def test_a_replay_client_needs_no_budget_and_calls_nothing(tmp_path):
    client = InstrumentedClient(tmp_path, mode=Mode.REPLAY)
    assert client.calls_made == 0
    with pytest.raises(SpendNotAuthorised):
        client.run_live("G2-01", "result", "prompt", tmp_path / "mcp.json")
    assert client.calls_made == 0, "a refused run still counted a call"


def test_the_budget_is_a_ceiling_and_not_a_suggestion(tmp_path):
    client = InstrumentedClient(tmp_path, mode=Mode.OBSERVED, live_call_budget=1)
    client.calls_made = 1
    with pytest.raises(SpendNotAuthorised) as refused:
        client.run_live("G2-01", "result", "prompt", tmp_path / "mcp.json")
    assert "budget" in str(refused.value)


# ── what the model was shown, as bytes ─────────────────────────────────────

def test_the_tool_result_is_read_as_bytes_not_as_reparsed_json(tmp_path):
    payload = 'GATE2_WITHHELD ‮ reordered \ud800'
    path = _transcript(tmp_path, [{"type": "tool_result", "content": payload}])
    block = extract_tool_result(path.read_bytes())
    assert block == payload.encode("utf-8", "surrogatepass")


def test_a_transcript_with_no_tool_result_reports_NOTHING_not_empty(tmp_path):
    """"The model was shown nothing" and "we could not tell" must differ."""
    path = _transcript(tmp_path, [{"type": "text", "text": "completed"}])
    assert extract_tool_result(path.read_bytes()) is None
    client = InstrumentedClient(tmp_path, mode=Mode.REPLAY)
    observation = client.replay("G2-01", "result", path)
    assert observation.tool_result_bytes is None
    assert observation.note and "observed nothing" in observation.note


def test_one_unparseable_line_costs_that_line_and_not_the_file(tmp_path):
    path = tmp_path / "t.jsonl"
    path.write_text("not json\n" + json.dumps(
        {"message": {"content": [{"type": "tool_result", "content": "kept"}]}}) + "\n")
    assert extract_tool_result(path.read_bytes()) == b"kept"


# ── the comparison that makes it evidence ──────────────────────────────────

def test_a_reordered_but_equivalent_result_is_NOT_identical(tmp_path):
    """`json.loads(a) == json.loads(b)` would call these the same.

    The question is which BYTES reached the model, so the comparison is on bytes.
    A mediator that re-serialises a result has changed what the model sees even
    when the object is equivalent.
    """
    emitted = b'{"a":1,"b":2}'
    path = _transcript(tmp_path, [{"type": "tool_result", "content": '{"b":2,"a":1}'}])
    client = InstrumentedClient(tmp_path, mode=Mode.REPLAY)
    observation = InstrumentedClient.compare(
        client.replay("G2-01", "result", path), emitted)
    assert observation.identical is False
    assert json.loads(observation.tool_result_bytes) == json.loads(emitted), (
        "the two are equivalent as objects, which is exactly why byte equality "
        "is the check and object equality is not")


def test_identical_bytes_compare_identical(tmp_path):
    emitted = b'{"a":1,"b":2}'
    path = _transcript(tmp_path, [{"type": "tool_result", "content": emitted.decode()}])
    client = InstrumentedClient(tmp_path, mode=Mode.REPLAY)
    observation = InstrumentedClient.compare(
        client.replay("G2-01", "result", path), emitted)
    assert observation.identical is True


def test_the_receipt_records_which_mode_produced_it(tmp_path):
    """OBSERVED and REPLAY are different strengths of evidence and say so."""
    path = _transcript(tmp_path, [{"type": "tool_result", "content": "x"}])
    record = InstrumentedClient(tmp_path, mode=Mode.REPLAY).replay(
        "G2-01", "result", path).as_record()
    assert record["mode"] == Mode.REPLAY
    assert record["tool_result"] == "x" and record["tool_result_len"] == 1
