"""Run ASTRA's FIT exam against the LIVE tree instead of his frozen snapshot.

`test_astra_fit_independent.py` and `test_astra_fit_followup.py` are vendored
byte-for-byte from the exam at 0ba36c8 and must stay that way; they are the
acceptance set and editing them would be grading ourselves. They do
`from probe_support import *`, and ASTRA's `probe_support` derives everything
from its own location: `SOURCE = ROOT/'source'` and
`BOUNDARY = SOURCE/'gauntlet/boundary'`, which it puts first on `sys.path`.

Left alone, that means the exam imports ASTRA's frozen copy of the candidate,
which is exactly right for reproducing his verdict and exactly wrong for fixing
it. Every run would grade the commit he examined, no matter what this branch
did, and the tests would keep failing in a way no edit could ever move.

So a live exam root is assembled under /private/tmp: every exam file symlinked
from ASTRA's directory so nothing is copied or reinterpreted, `source` pointing
at THIS working tree, and `evidence` a fresh empty directory of our own. That
last one matters. Evidence is written on every run, and symlinking it would
overwrite the exam's own record, which is the mistake already made once today
with the materialisation receipt.

Verified at build time: ASTRA's `source/gauntlet/boundary` is byte identical to
0ba36c8, so the only difference between his run and ours is the branch under it.
"""
from __future__ import annotations

import pathlib
import sys

EXAM = (pathlib.Path.home() / "Desktop" / "SUNGLASSES_ASTRA_REVIEW_2026-09-04"
        / "GATE2_FIT_0ba36c8_2026-09-13")
LIVE = pathlib.Path("/private/tmp") / "GATE2_FIT_LIVE"
REPO = pathlib.Path(__file__).resolve().parents[3]

# Written by the exam, never read from it. Anything else is ASTRA's and is
# linked rather than copied so it cannot be edited by accident.
FRESH = {"evidence", "source", "__pycache__", ".pytest_cache"}

# COPIED, NOT LINKED, and this is the whole reason the first version of this
# file did nothing. `probe_support` computes ROOT from
# `Path(__file__).resolve().parent`, and `resolve()` follows symlinks. Reached
# through a link, it resolved straight back into ASTRA's directory, so ROOT was
# his, SOURCE was his, BOUNDARY was his frozen copy of the candidate, and the
# whole exam ran against 0ba36c8 while appearing to run against this branch. A
# traceback pointing at his Desktop path is what gave it away.
#
# Copied byte for byte, and the digest is asserted below, so this relocates the
# file without reinterpreting it.
COPIED = {"probe_support.py"}


def _build_live_root() -> pathlib.Path | None:
    if not EXAM.is_dir():
        return None
    LIVE.mkdir(parents=True, exist_ok=True)
    import hashlib
    import shutil

    for item in EXAM.iterdir():
        if item.name in FRESH:
            continue
        target = LIVE / item.name
        if item.name in COPIED:
            if not target.exists() or target.read_bytes() != item.read_bytes():
                if target.is_symlink():
                    target.unlink()
                shutil.copy2(item, target)
            assert hashlib.sha256(target.read_bytes()).hexdigest() == \
                hashlib.sha256(item.read_bytes()).hexdigest(), item.name
            continue
        if target.is_symlink() or target.exists():
            continue
        target.symlink_to(item)

    source = LIVE / "source"
    if not source.is_symlink():
        source.symlink_to(REPO)
    (LIVE / "evidence").mkdir(exist_ok=True)
    return LIVE


_live = _build_live_root()
if _live is not None and str(_live) not in sys.path:
    # After the boundary path, so `import batch` still resolves to the tree and
    # only `probe_support` comes from the exam.
    sys.path.append(str(_live))
