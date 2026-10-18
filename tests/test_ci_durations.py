"""tools/ci_durations.py turns pytest's `--durations` lines into the COST table of tests/ci_shard.py."""
import importlib.util
import pathlib

_spec = importlib.util.spec_from_file_location(
    "ci_durations", pathlib.Path(__file__).resolve().parents[1] / "tools" / "ci_durations.py")
ci = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ci)

LOG = """\
2026-10-16T15:00:01.1Z ============ slowest durations ============
2026-10-16T15:00:01.1Z 74.49s call     tests/test_a.py::test_x[p1]
2026-10-16T15:00:01.1Z 10.01s setup    tests/test_a.py::test_x[p1]
2026-10-16T15:00:01.1Z 0.50s teardown tests/test_a.py::test_x[p1]
2026-10-16T15:00:01.1Z 5.00s call     tests/test_b.py::test_y
2026-10-16T15:00:01.1Z 3.00s call     tests/test_c.py::test_z
2026-10-16T15:00:01.1Z (1 durations < 0.005s hidden.  Use -vv to show these durations.)
2026-10-16T15:00:01.1Z ===== 3 passed in 80.00s (0:01:20) =====
"""


def test_setup_call_and_teardown_of_one_test_are_added():
    got = ci.parse_durations(LOG)
    assert got["tests/test_a.py::test_x[p1]"] == 74.49 + 10.01 + 0.5
    assert len(got) == 3


def test_the_summary_line_and_the_hidden_note_are_not_read_as_tests():
    assert set(ci.parse_durations(LOG)) == {
        "tests/test_a.py::test_x[p1]", "tests/test_b.py::test_y", "tests/test_c.py::test_z"}


def test_files_are_summed_over_every_log_given():
    both = ci.parse_durations(LOG) + ci.parse_durations(LOG)
    assert ci.per_file(both)["tests/test_b.py"] == 10.0


def test_the_cost_block_lists_files_at_the_threshold_and_means_the_rest():
    block = ci.cost_block(ci.per_file(ci.parse_durations(LOG)))
    assert 'DEFAULT_COST = 4' in block      # mean of 5 and 3
    assert '"tests/test_a.py": 85,' in block
    assert "test_b.py" not in block.split("COST = {")[1]


def test_a_log_without_durations_reads_as_empty():
    assert not ci.parse_durations("collected 3 items\n3 passed in 1.00s\n")
