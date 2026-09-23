"""`-k` exempts a run from the full-suite guard; breadth is what makes that safe.

The pre-collection check asks whether a filter is PRESENT. Presence is not
breadth, so `pytest tests -k "test_"` selected 4,127 of 4,127 rows and was not
gated at all. This is the other half, and it lives after collection because
breadth is not knowable before it.
"""
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("_root_conftest", ROOT / "conftest.py")
_root = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_root)

broad = _root._filter_is_broad
FRACTION, ABSOLUTE = _root.BREADTH_FRACTION, _root.BREADTH_ABSOLUTE

# The live tree, measured 2026-09-22, so the rows below are not invented.
TREE = 4127


def test_a_filter_that_takes_the_whole_tree_is_broad():
    assert broad(TREE, TREE)                       # -k "test_" : 100%


def test_a_filter_that_takes_a_large_share_is_broad():
    assert broad(1599, TREE)                       # -k proxy : 39%


def test_the_narrow_runs_people_actually_iterate_with_are_not_broad():
    assert not broad(1, TREE)                      # one node id
    assert not broad(305, TREE)                    # -k scan : 7%, under both
    assert not broad(107, TREE)                    # -k pattern


def test_both_thresholds_bite_independently():
    """Either one alone must be enough, or a big tree hides a big selection."""
    # Under the fraction, over the absolute: a 600-row selection of a 100k tree
    # is still 600 rows of contention.
    assert broad(ABSOLUTE, 100_000)
    # Over the fraction, under the absolute: a small tree can still be taken
    # whole, and taking it whole is the thing being refused.
    assert broad(30, 100)


def test_an_empty_or_unknown_subject_is_not_reported_as_broad():
    """It is not this check's business, and it must not invent a refusal.

    The pre-collection guard owns "nothing to run"; a zero here means the
    counters were never populated, and refusing on that would be a guard firing
    on its own blindness.
    """
    assert not broad(0, TREE)
    assert not broad(10, 0)
    assert not broad(None, None)


def test_a_same_number_comparison_would_refuse_every_filtered_run():
    """Why the hook ORDER matters, stated as a property this can actually test.

    pytest's own `-k` deselection happens inside `pytest_collection_modifyitems`.
    If the hook recording COLLECTED ran after it, both counters would hold the
    SELECTED count -- and `broad(n, n)` is 100%, so every filtered run would be
    refused, including the one-node-id runs people iterate with. That is the
    degenerate case, and it is detectable:
    """
    assert broad(305, 305)      # same number -> 100% -> refused
    assert not broad(305, TREE)  # real counters -> 7% -> allowed
    # Measured live while the lock was held, which is the integration half this
    # unit cannot reach: `-k proxy` refused with "SELECTED 1599 of 4127 rows
    # (39%)". Two different numbers, so the tryfirst hook did record the
    # pre-deselection count.
