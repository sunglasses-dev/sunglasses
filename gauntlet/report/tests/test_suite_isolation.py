"""The suite never reads the run file or ledger record that sits beside produce.py.

`produce.build()` imports both from fixed paths in the source tree, and a tree that has had a
real run in it holds a run file older than the clock these tests pin (EXEC_RUN_STALE on eleven
rows). conftest points both paths at an empty folder for the whole session. These rows fail if
that stops being true, on a clean tree as well as a dirty one.
"""
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import produce  # noqa: E402

TREE = HERE.parent


def test_the_run_file_path_is_outside_the_source_tree_and_empty():
    assert TREE not in produce.EXECUTION_RUN.parents and not produce.EXECUTION_RUN.exists()


def test_the_ledger_record_path_is_outside_the_source_tree_and_empty():
    assert TREE not in produce.LEDGER_RECORD.parents and not produce.LEDGER_RECORD.exists()
