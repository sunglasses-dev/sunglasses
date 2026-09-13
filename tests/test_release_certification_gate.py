"""The release gate certifies ONE exact tree, never a family of trees.

Found 2026-09-13 by an independent review of the release workflow (PR #159):
`scripts/require_release_certification.py` matched CI run heads on their first
seven characters, so a second commit sharing a seven-character prefix with a
certified commit borrowed its run. The reviewer mined such a commit in seven
seconds. These tests drive the real script through a `gh` shim that answers
from fixtures on disk (synthetic replies, clearly not downloaded from GitHub),
so every branch of the decision is executed rather than read.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "require_release_certification.py"

CERTIFIED = "7764e2287347027b23bc2c4fcb7622ad22c3f83b"
# Same first seven characters, a different commit. This is the reviewer's
# mined collision, kept verbatim so the negative is the real shape.
COLLIDING = "7764e22ba1f3c8204dcc13723015cb026e8472da"
OTHER = "35c5e775f0674a73c8de7793dd1e728efe01d2f0"
RUN_ID = 999000159
LEGS = ["classify", "fast", "coverage", "certify"] + [
    f"integrity (3.{v})" for v in range(9, 15)
]

SHIM = """#!%s
import json, pathlib, sys
here = pathlib.Path(__file__).resolve().parent
args = sys.argv[1:]
if args[:2] == ["run", "list"]:
    print((here / "runs.json").read_text())
elif args[:2] == ["run", "view"]:
    print((here / "detail.json").read_text())
else:
    raise SystemExit("unexpected gh call: %%r" %% (args,))
"""


@pytest.fixture
def api(tmp_path):
    """A gh shim whose replies name ONLY the certified commit as having a run."""
    shim = tmp_path / "gh"
    shim.write_text(SHIM % sys.executable)
    shim.chmod(0o755)
    runs = [{"databaseId": RUN_ID, "headSha": CERTIFIED, "status": "completed",
             "conclusion": "success", "event": "push"}]
    detail = {"headSha": CERTIFIED,
              "jobs": [{"name": n, "status": "completed", "conclusion": "success"}
                       for n in LEGS]}
    (tmp_path / "runs.json").write_text(json.dumps(runs))
    (tmp_path / "detail.json").write_text(json.dumps(detail))
    return tmp_path


def gate(api, sha):
    env = dict(os.environ, PATH=str(api) + os.pathsep + os.environ["PATH"])
    return subprocess.run([sys.executable, str(SCRIPT), sha],
                          capture_output=True, text=True, env=env, timeout=60)


def test_the_certified_full_sha_passes(api):
    r = gate(api, CERTIFIED)
    assert r.returncode == 0, r.stderr
    assert "RELEASE CERTIFIED" in r.stdout


def test_an_uncertified_commit_is_refused(api):
    r = gate(api, OTHER)
    assert r.returncode == 2
    assert "no pattern-integrity run exists" in r.stderr


def test_a_prefix_collision_cannot_borrow_the_certified_run(api):
    # The reviewer's bypass: same first seven characters, different tree.
    assert COLLIDING[:7] == CERTIFIED[:7] and COLLIDING != CERTIFIED
    r = gate(api, COLLIDING)
    assert r.returncode == 2, r.stdout + r.stderr
    assert "no pattern-integrity run exists" in r.stderr


@pytest.mark.parametrize("short", [CERTIFIED[:7], CERTIFIED[:12], CERTIFIED[:39], ""])
def test_anything_shorter_than_a_full_sha_is_refused_before_any_api_call(api, short):
    r = gate(api, short)
    assert r.returncode == 2
    assert "full 40-character commit sha" in r.stderr


def test_a_detail_reply_for_a_different_head_is_refused(api):
    detail = json.loads((api / "detail.json").read_text())
    detail["headSha"] = COLLIDING
    (api / "detail.json").write_text(json.dumps(detail))
    r = gate(api, CERTIFIED)
    assert r.returncode == 2
    assert "different head sha" in r.stderr


def test_uppercase_input_is_the_same_commit(api):
    r = gate(api, CERTIFIED.upper())
    assert r.returncode == 0, r.stderr


def test_the_seven_character_comparison_is_gone():
    src = SCRIPT.read_text()
    assert "[:7]" not in src
    assert "startswith(args" not in src
