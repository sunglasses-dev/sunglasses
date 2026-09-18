"""Import shim, so ASTRA's `list_crossings.py` stays byte-identical in the tree.

His file does `from seam_controls import build, final`, and our copy of his seam
controls is collected as `test_seam_controls.py`. Renaming his import would make
the file no longer his; a four-line shim costs nothing and keeps "verbatim"
checkable by sha256. Not named `test_*`, so pytest does not collect it twice.
"""
from test_seam_controls import build, final, wire  # noqa: F401
