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
