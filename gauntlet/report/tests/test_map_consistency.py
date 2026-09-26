"""The map may not hold open a question its own consumer has already answered.

ASTRA capmap-88403e5-r1, NO GO (2026-09-23): `release_any_old_workers` sat in
`unclassified` with a 9-14 open question while `gen2/adapter.py` listed it as
IMPLEMENTED (added 9-22 with its test) and `execute.py` drove it from the
mediator's WORKER_OUTPUT receipts. `needs_of` never yields an implemented op,
so the stale entry changed no count and nothing noticed: a map can drift from
the code it describes in exactly the places no number depends on.

Reads the map IN THE TREE (not the suite's reviewed copy), because the defect
is in the file a reviewer is asked to approve.
"""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "boundary"))

from gen2 import adapter  # noqa: E402

MAP = HERE.parent / "capability_map.json"


def test_no_implemented_op_is_still_listed_as_an_open_question():
    unclassified = json.loads(MAP.read_text())["unclassified"]
    stale = sorted(adapter.IMPLEMENTED & set(unclassified))
    assert not stale, (
        f"{stale} are IMPLEMENTED in gen2/adapter.py and still open in the map; "
        "reconcile the entry with the implementation (a basis for the route "
        "question, never an executed witness without a run)")


def test_the_row_can_fail(tmp_path):
    """Control: the same check, on a map with an implemented op put back as open."""
    data = json.loads(MAP.read_text())
    op = sorted(adapter.IMPLEMENTED)[0]
    data["unclassified"][op] = {"open_question": "control"}
    assert adapter.IMPLEMENTED & set(data["unclassified"])
