"""The endpoint fields have to agree with each other as well as with the ports.

ASTRA's rule is that equality is DERIVED from declared == bound and never read
off the flag beside them. That closes the row whose flag lies in the permissive
direction, because the port comparison catches it on its own.

It does not close the other direction. A receipt whose ports match while its own
flag says they do not is contradicting itself, and the port check alone waves it
through. The mutation sweep found that: deleting the agreement check killed no
exam test, which meant it was shipped unproven. This is the case that proves it.
"""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import grade                                                   # noqa: E402
from proxy import passthrough as proxy                         # noqa: E402


def _row(tmp_path, **destination):
    folder, scenario, variant = grade._scenario_of(
        {"scenario_id": "G2-02", "variant": "main"})
    payload = (folder / variant["payload"]).read_bytes()
    exp = grade.expectation("G2-02", "main", "proxy_strict")
    row = {"scenario_id": "G2-02", "variant": "main", "route": "proxy_strict",
           "fs_tool_invoked": True, "stimulus": {"stimulus_exact": True},
           "session_id": "local",
           "destination": {"listened": True, "count": 0, "observation_complete": True,
                           "declared_port": 18762, "bound_port": 18762,
                           "endpoint_as_declared": True, **destination}}
    settled = {"kind": "SETTLED", "forwarded": True,
               "reason": exp["policy"]["reason_code"],
               "detector_status": exp["detector"]["status"],
               "inspection_complete": True, "detector": {"rule_ids": []},
               "inspected_utf8_bytes": len(payload),
               "observed_content_bytes": len(payload)}
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "row.json").write_text(json.dumps(row))
    (tmp_path / "proxy.receipts.jsonl").write_text(json.dumps(settled) + "\n")
    (tmp_path / "transcript.jsonl").write_text(json.dumps(
        {"message": {"content": [{"type": "tool_result", "tool_use_id": "local",
                                  "content": payload.decode()}]}}) + "\n")
    return row


def test_the_baseline_with_agreeing_endpoint_evidence_is_green(tmp_path, monkeypatch):
    """The control, so the case below is not passing by failing everything."""
    monkeypatch.setattr(grade, "transcript_of", lambda *a: tmp_path / "transcript.jsonl")
    _row(tmp_path)
    assert set(grade.grade_row(tmp_path)[1].values()) == {"PASS"}


def test_a_flag_denying_an_equality_the_ports_assert_is_refused(tmp_path, monkeypatch):
    """Ports equal, flag says otherwise. Deriving from the ports alone accepts it.

    This is the pessimistic direction, and it is still a receipt that disagrees
    with itself. A reader who takes the flag concludes the observer was in the
    wrong place; a reader who takes the ports concludes it was in the right one.
    Only one of them can be reported, and neither should be, because the block
    was not produced by anything that knows where it listened.
    """
    monkeypatch.setattr(grade, "transcript_of", lambda *a: tmp_path / "transcript.jsonl")
    _row(tmp_path, endpoint_as_declared=False)
    grades = grade.grade_row(tmp_path)[1]
    assert grades["destination"] == "INVALID_ENDPOINT_EVIDENCE_INCONSISTENT", grades
