"""The exam must run against the tree that is being tested, and say so.

`source` inside the live exam root is what makes `probe_support` resolve SOURCE
and BOUNDARY, so it decides which candidate the whole exam measures. It used to
be created only when ABSENT, under a live root at a fixed path shared by every
checkout on the machine. The first worktree to build that root won: every other
one inherited a `source` pointing at the first one's code, ran the exam against
a tree it was not testing, and reported the result under its own branch's name.

There is no red run to show for that, which is the point — it fails by being
green about the wrong artifact. So the row is the postcondition instead.
"""
import hashlib
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import conftest  # noqa: E402


def test_the_live_root_is_keyed_to_this_checkout():
    """Eighty-one worktrees share this repository; they may not share this."""
    assert conftest.LIVE.name.startswith("GATE2_FIT_LIVE-"), conftest.LIVE
    expected = hashlib.sha256(str(conftest.REPO).encode()).hexdigest()[:12]
    assert conftest.LIVE.name == f"GATE2_FIT_LIVE-{expected}", conftest.LIVE

    # A DIFFERENT checkout keys somewhere else. Without this the assertion above
    # would pass for a constant.
    other = hashlib.sha256(b"/somewhere/else/wt-other").hexdigest()[:12]
    assert other != expected


def test_the_exam_source_points_at_the_tree_under_test():
    """The one that would have been wrong, silently, for every worktree but one."""
    if conftest._live is None:
        import pytest
        pytest.skip("no exam delivery on this machine")

    source = conftest.LIVE / "source"
    assert source.is_symlink(), f"{source} is not a symlink to the tree under test"
    assert source.readlink() == conftest.REPO, (
        f"the exam would run against {source.readlink()} while reporting on "
        f"{conftest.REPO}")

    # And the tree it points at is really this one: a file only this checkout
    # has at this path, reached THROUGH the link.
    assert (source / "gauntlet" / "boundary" / "tests" / __file__.rsplit("/", 1)[-1]).is_file()


def test_the_modules_under_test_resolve_to_this_checkout():
    """`batch`, `grade`, `proxy` and `destination` must be THIS tree's.

    `probe_support` inserts a boundary directory of its own choosing at
    `sys.path[0]`, ahead of anything the conftest arranged, and every
    `test_astra_fit_*` module imports it BEFORE it imports these. So the
    conftest binds them first: once a module is in `sys.modules` no later path
    edit can re-point it.

    This is the row that would have caught the 2026-09-22 contamination, where
    two scratch copies both graded a third checkout and agreed with each other.
    """
    import batch
    import grade
    from proxy import passthrough
    from destination import sink

    repo = conftest.REPO
    for module in (batch, grade, passthrough, sink):
        resolved = pathlib.Path(module.__file__).resolve()
        assert resolved.is_relative_to(repo), (
            f"{module.__name__} came from {resolved}, not from the checkout "
            f"under test at {repo}")


def test_the_exam_cannot_re_point_a_module_once_it_is_bound():
    """The mechanism, not just the outcome.

    Putting the exam's boundary directory back at `sys.path[0]` — exactly what
    `probe_support` does — must not change what `batch` is, because it is
    already imported.
    """
    import batch

    before = batch.__file__
    intruder = "/private/tmp/some-other-checkout/gauntlet/boundary"
    sys.path.insert(0, intruder)
    try:
        import batch as again
        assert again.__file__ == before, (
            "an import after a path change re-pointed a bound module")
    finally:
        sys.path.remove(intruder)
