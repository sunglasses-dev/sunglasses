"""The reaped-root resolver finds the delivery, and nothing else.

16 of the delivered scenarios carry absolute `payload_ref` paths under
`/private/tmp/GATE3_DESIGN_REVIEW_2026-09-13/`, which macOS reaps. The same
package lives durably on the Desktop with all 76 referenced files present.

The risk in resolving a second address is that it becomes a resolver that finds
SOMETHING — which is worse than the failure it replaces, because a stimulus that
is not the one the seed names is the exact defect this harness exists to catch.
Every row below is about refusing.
"""
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import runner  # noqa: E402


def test_a_reaped_path_resolves_to_the_durable_copy():
    reaped = runner._REAPED_ROOT / "fixtures" / "shared" / "H01.payload.txt"
    got = runner._durable(reaped)
    assert got != reaped, "did not resolve"
    assert got.is_file() and runner._DURABLE_ROOT in got.parents


def test_a_reaped_path_with_no_counterpart_keeps_the_declared_address(tmp_path):
    """THE CONTROL. A missing fixture must still fail, and the error must name
    the address the SEED declares — not a guess about where it might live."""
    ghost = runner._REAPED_ROOT / "fixtures" / "shared" / "definitely-not-here.txt"
    assert runner._durable(ghost) == ghost


def test_a_path_outside_the_reaped_root_is_untouched(tmp_path):
    """The resolver must not become a search path for every missing file."""
    elsewhere = tmp_path / "somewhere" / "other.txt"
    assert runner._durable(elsewhere) == elsewhere


def test_an_existing_path_is_returned_unchanged(tmp_path):
    """On a machine where the temp copy survives, nothing changes."""
    real = tmp_path / "present.txt"
    real.write_text("x")
    assert runner._durable(real) == real
