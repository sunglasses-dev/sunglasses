"""Point the suite at a REVIEWED copy of the capability map.

`load_map` refuses a map whose `review_state` is not `reviewed` (added
2026-09-22, and that gate has its own rows in the acceptance controls). The map
in the tree is `unreviewed` today, so without this every row that reaches
`produce.build()` gets `coverage: unavailable` and fails on missing keys — not
because the thing it tests is broken, but because a different gate fired first.

A suite that answered this by weakening the gate would be the usual death: the
gate stops meaning anything and the next unreviewed map publishes a ceiling.
So the gate stays exact and the SUITE supplies a reviewed copy.

NOTHING HERE MARKS THE REAL MAP REVIEWED. The file in the tree is untouched;
only a human review changes that.
"""
import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import classify  # noqa: E402


@pytest.fixture(autouse=True, scope="session")
def reviewed_map_for_the_suite(tmp_path_factory):
    original = classify.MAP_PATH
    data = json.loads(pathlib.Path(original).read_text())
    data["review_state"] = classify.REVIEWED
    path = tmp_path_factory.mktemp("capmap-session") / "reviewed.json"
    path.write_text(json.dumps(data))
    classify.MAP_PATH = path
    yield path
    classify.MAP_PATH = original
