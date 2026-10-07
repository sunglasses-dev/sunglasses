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
    # Reviewed THROUGH THE MECHANISM (review.record), never by typing the state:
    # a typed `reviewed` is exactly what load_map now refuses.
    import review
    path = tmp_path_factory.mktemp("capmap-session") / "capability_map.json"
    path.write_text(pathlib.Path(original).read_text())
    review.record(path, "**GO**: test-suite fixture, not a real review.\n", verdict="GO",
                  reviewer="TEST-FIXTURE", round_id="suite")
    classify.MAP_PATH = path
    yield path
    classify.MAP_PATH = original


OPEN_MAP = HERE / "fixtures" / "capability_map.open.json"


@pytest.fixture(scope="session")
def refused_report(tmp_path_factory):
    """A real refusal, built from a map that still has unclassified operations.

    The tree map used to be open, so `produce.build()` on it was the refusal the
    refusal controls need. Closing the map ended that, and a closed map with no
    executed rows is meant to refuse for another reason (EXEC_NONE, see the last
    test in test_acceptance_controls). So the refusal controls get their own open
    map, reviewed THROUGH THE MECHANISM like the session copy above, and the
    session map is put back afterwards.
    """
    import produce
    import review
    path = tmp_path_factory.mktemp("capmap-open") / "capability_map.json"
    path.write_text(OPEN_MAP.read_text())
    review.record(path, "**GO**: test-suite fixture, not a real review.\n", verdict="GO",
                  reviewer="TEST-FIXTURE", round_id="suite")
    session = classify.MAP_PATH
    classify.MAP_PATH = path
    try:
        report, _ = produce.build(run_id="fixture")
    finally:
        classify.MAP_PATH = session
    return report
