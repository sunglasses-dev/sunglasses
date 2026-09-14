"""ASTRA's v1.2 examiner corrections, run as he wrote them.

GATE2-EXAM-CORRECTION-v1.2 is his ruling on the three things the live pair
exposed, and all three were his, at the head he had certified FIT:

  1. count primary AND `also_matched` ids from the accepted, causally bound
     worker completion, which is where GLS-SD-001 was all along;
  2. grade detector and policy for the typed PRIMARY request only, preserving
     unrelated settlements separately;
  3. bind delivered original content to the correlated native response, never
     assuming an outbound argument is an inbound result.

I reported all three from the pair and repaired none of them. Two would have
turned my own row's FAILs into passes in an instrument he had just certified,
and the third I filed as a substantive gap for him to rule on rather than as a
product defect. He has since ruled that leaving the certified instrument alone
was correct. This file is the other half of that: his correction, vendored, not
my reimplementation of it.

RUN AS A SUBPROCESS because his file is a script rather than a pytest module.
Importing it would execute it at collection time, and renaming or restructuring
it would break the byte identity that makes it his artifact rather than mine.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

BOUNDARY = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BOUNDARY))          # as every other test file here does
SCRIPT = BOUNDARY / "tests" / "astra_corrections_v1_2.py"
GRADER = BOUNDARY / "grader_v1_2.py"

# Pinned, so a change to either arrives as a visible break rather than a drift.
SCRIPT_SHA256 = "5de874d4910d37a4cb76f8e0b8fec0db397257562b4f12da811d721ba5495bba"
GRADER_SHA256 = "ee5cb764de2ef008d5095985df807234e190551d4c0e1e9bd6b42b4c292862b7"


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_the_vendored_correction_is_byte_identical():
    assert _sha(SCRIPT) == SCRIPT_SHA256, SCRIPT
    assert _sha(GRADER) == GRADER_SHA256, GRADER


def test_all_43_correction_checks_pass_including_the_restorations():
    """His own count, reproduced here rather than asserted from his report.

    The three reverts are the restoration control: each puts one correction back
    the way it was and requires the FAIL it caused to return, so a correction
    that did nothing could not hide inside a green run. `baseline_restored` then
    requires both live rows to grade clean again afterwards.
    """
    completed = subprocess.run([sys.executable, "-B", str(SCRIPT)],
                               cwd=str(BOUNDARY), capture_output=True, text=True,
                               env={"PYTHONPATH": str(BOUNDARY), "PATH": "/usr/bin:/bin"})
    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout.strip().splitlines()[-1])
    assert summary["failed"] == [], summary
    assert summary["passed"] == 43, summary

    cases = json.loads((BOUNDARY / "tests" / "evidence"
                        / "correction_tests.json").read_text())["cases"]
    names = {c["case"] for c in cases}
    for control in ("revert_alias_correction", "revert_primary_scope",
                    "revert_response_reference", "baseline_restored"):
        assert control in names, sorted(names)
