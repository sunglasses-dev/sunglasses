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

import hashlib
import pathlib
import sys

# THE NEWEST EXAM, resolved rather than hardcoded. Round 2 arrived as its own
# directory carrying its own probe_support, evidence and mutations, and pinning
# the round 1 path would have run the new acceptance set against the old exam's
# support code. Both deliveries' test_independent.py and test_followup.py are
# byte identical and so is probe_support, verified before this changed, so the
# newest directory supersedes rather than competes.
_BOUNDARY = str(pathlib.Path(__file__).resolve().parents[1])
if _BOUNDARY not in sys.path:      # appended, never inserted: import order is the suite's
    sys.path.append(_BOUNDARY)
import review_root                                         # noqa: E402

_EXAMS = sorted(review_root.ROOT.glob("GATE2_FIT_*"))
EXAM = _EXAMS[-1] if _EXAMS else review_root.ROOT / "GATE2_FIT_0ba36c8_2026-09-13"
REPO = pathlib.Path(__file__).resolve().parents[3]

# ONE LIVE ROOT PER CHECKOUT, not one for the machine. This was a fixed path,
# and the tree under it persists between runs while `source` below is only
# created when it is ABSENT. So the first worktree to build it won: every other
# checkout that ran afterwards inherited a `source` pointing at the first one's
# code and ran the exam against a tree it was not testing, reporting the result
# under its own branch's name. That is the failure this file's own COPIED
# comment describes, arrived at from the other direction, and eighty-one
# worktrees share this repository.
#
# Keyed by the checkout path so two of them cannot collide, and short so the
# directory stays readable in a traceback.
LIVE = (pathlib.Path("/private/tmp") /
        ("GATE2_FIT_LIVE-" + hashlib.sha256(str(REPO).encode()).hexdigest()[:12]))

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
#
# `ledger_contender.py` JOINS IT for the same reason, found 2026-09-22 and
# missed the first time. It is a SCRIPT, launched as
# `python3 <root>/ledger_contender.py`, and Python sets `sys.path[0]` to the
# RESOLVED directory of the script. Through a link that is ASTRA's directory,
# where `source` does not exist — so `probe_support` there computes a BOUNDARY
# that is not on disk, `from runner import Ledger` raises
# ModuleNotFoundError, all eight contenders die before writing `.ready`, and
# `test_r7_concurrent_overspend_refuses` fails waiting for them.
#
# The symptom named the wrong layer: the failure looked like a concurrency or
# ledger problem, and the eight children were writing the real answer into
# their own logs the whole time.
COPIED = {"probe_support.py", "ledger_contender.py"}


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
            # A SYMLINK IS ALWAYS WRONG HERE, whatever its bytes say. Both
            # `exists()` and `read_bytes()` follow the link, so a link pointing
            # at the very file being copied passed this check and was left in
            # place — a guard whose whole purpose is to stop a symlink, defeated
            # by one that happened to have the right contents.
            #
            # It mattered the moment a SCRIPT joined the set: `sys.path[0]` is
            # the RESOLVED directory of the script Python was asked to run.
            if (target.is_symlink() or not target.exists()
                    or target.read_bytes() != item.read_bytes()):
                if target.is_symlink() or target.exists():
                    target.unlink()
                shutil.copy2(item, target)
            assert hashlib.sha256(target.read_bytes()).hexdigest() == \
                hashlib.sha256(item.read_bytes()).hexdigest(), item.name
            continue
        if target.is_symlink() or target.exists():
            continue
        target.symlink_to(item)

    # RE-POINTED IF IT IS WRONG, never merely created if it is missing. The
    # per-checkout root above should make a stale one impossible; this is the
    # assertion that it did, and it costs a readlink. A `source` pointing
    # somewhere else means the whole exam runs against another tree while
    # appearing to run against this branch, which is the single most expensive
    # way this harness can be wrong and the hardest to see in a green run.
    source = LIVE / "source"
    if source.is_symlink() and source.readlink() != REPO:
        source.unlink()
    if not source.is_symlink():
        source.symlink_to(REPO)

    # FRESH EVERY SESSION, and this is a correctness matter rather than tidiness.
    # The exam writes its evidence here and some of it is STATE, not a record:
    # `test_r7_concurrent_overspend_refuses` starts eight contenders against a
    # ledger in this tree and asserts exactly one of them wins. On a second run
    # the ledger still holds the first run's charge, so all eight correctly
    # refuse, nobody reports a win, and the test fails while the code is right.
    # An hour could go into "fixing" that. The directory is ours, never ASTRA's,
    # and a charge from a previous run is not evidence about this one.
    shutil.rmtree(LIVE / "evidence", ignore_errors=True)
    (LIVE / "evidence").mkdir(exist_ok=True)

    # ASTRA'S OWN RECEIPTS ARE SEEDED BACK IN, the top-level files only. Some
    # tests READ his record rather than writing one: test_r6_package_receipts_current
    # reads package_checksum_validation.final.json and has nothing to say without
    # it. The per-run subtrees (independent, followup, native_pair) are NOT
    # seeded, because those are outputs and his r7_concurrent even carries a
    # spent ledger that would re-create the staleness this wipe exists to stop.
    # Copies, so a test that overwrites one touches ours and never his.
    for item in (EXAM / "evidence").iterdir():
        if item.is_file():
            shutil.copy2(item, LIVE / "evidence" / item.name)
    return LIVE


_live = _build_live_root()
if _live is not None and str(_live) not in sys.path:
    # After the boundary path, so `import batch` still resolves to the tree and
    # only `probe_support` comes from the exam.
    sys.path.append(str(_live))

# BOUND TO THIS CHECKOUT BEFORE ANY TEST CAN IMPORT THE EXAM.
#
# The append above was supposed to be the whole protection, and it is not.
# `probe_support` derives BOUNDARY from the exam root's `source` link and then
# does `sys.path.insert(0, str(BOUNDARY))`, which puts a tree of its choosing
# AHEAD of everything this file arranged. Every `test_astra_fit_*` module runs
# `from probe_support import *` on the line BEFORE `import batch, grade`, so the
# ordering that comment depends on is reversed by the module it is importing.
#
# It cost a real result. On 2026-09-22 two scratch copies of this tree ran the
# suite, both resolved `batch`, `grade` and `proxy` through a shared exam root
# whose `source` pointed at a THIRD checkout, and agreed with each other
# exactly — which was then reported as evidence that the suite is
# deterministic. They agreed because they were both grading the same code, and
# neither was grading its own. → GAUNTLET_PROVENANCE_AUDIT_2026-09-22.md
#
# `probe_support` is ASTRA's file, copied byte for byte with its digest
# asserted above, so it is not ours to change. Importing these HERE is: once a
# module is in `sys.modules`, no later `sys.path` edit can re-point it. The
# exam may still insert what it likes; it can no longer decide what `batch` is.
_BOUNDARY = str(REPO / "gauntlet" / "boundary")
if _BOUNDARY not in sys.path:
    sys.path.insert(0, _BOUNDARY)

import batch as _batch                                         # noqa: E402
import grade as _grade                                         # noqa: E402
from proxy import passthrough as _passthrough                  # noqa: E402
from destination import sink as _sink                          # noqa: E402

for _bound in (_batch, _grade, _passthrough, _sink):
    # The postcondition, asserted at import so a contaminated session cannot
    # reach a test. A suite that grades another checkout does not fail; it
    # reports on the wrong artifact and looks exactly like a clean run.
    assert pathlib.Path(_bound.__file__).resolve().is_relative_to(REPO), (
        f"{_bound.__name__} resolved to {_bound.__file__}, outside the checkout "
        f"under test at {REPO}. The exam has re-pointed the modules this suite "
        f"is supposed to be measuring.")


# ── the one trusted legacy context ──────────────────────────────────────────
# ASTRA's round 2 acceptance file builds its rows the way destination receipts
# were written before the endpoint group existed: no declared port, no bound
# port, no equality flag. Its baselines must grade clean, and E24 in round 5
# builds a row of the IDENTICAL shape and must not. Measured, those two rows are
# equal field for field, so nothing in a row can tell them apart and any rule
# that tried would be reading a coincidence.
#
# So the declaration is made HERE, about a file, not about a row. This harness
# knows which vendored acceptance file predates the group and says so out loud,
# for the duration of that file only. The grader never infers it: its own
# default refuses a missing group, which is what E24 requires, and what an
# absent producer would otherwise be able to hide behind.
import pytest                                                  # noqa: E402

LEGACY_ENDPOINT_SHAPE_FILES = {"test_astra_fit_round2.py"}


@pytest.fixture(autouse=True)
def _legacy_destination_shape(request):
    import grade
    legacy = request.path.name in LEGACY_ENDPOINT_SHAPE_FILES
    previous = grade.LEGACY_DESTINATION_SHAPE
    grade.LEGACY_DESTINATION_SHAPE = legacy
    try:
        yield
    finally:
        grade.LEGACY_DESTINATION_SHAPE = previous
# ── ONE RUN AT A TIME ───────────────────────────────────────────────────────
# The decision lives in `run_alone.py` so it can be imported and tested; see its
# docstring for why this guard exists and why it is not a pgrep.
import os as _os

import pytest as _pytest

# ONE COPY, and it lives on main at `tools/run_alone.py` so the scanner suites
# can take the SAME lock. A second copy here would be a second answer to one
# question, which is the whole defect this guard exists to stop: the two would
# drift, and the lane that lost the race would be certifying itself alone
# against a rule the other lane no longer follows.
if str(REPO / "tools") not in sys.path:
    sys.path.insert(0, str(REPO / "tools"))

from run_alone import (current_holder as _current_holder,
                       foreign_pytest as _foreign_pytest,
                       repo_lock_path as _repo_lock_path)

# KEYED ON THE REPOSITORY, not on this directory. The suite-local lock said
# "I ran alone" while another session's suite ran against another worktree of
# the same repo and burned the same cores. Three timing-sensitive rows moved
# across four otherwise identical runs because of it.
_LOCK = _repo_lock_path()


@_pytest.fixture(autouse=True, scope="session")
def one_run_at_a_time():
    holder = _current_holder(_LOCK)
    if holder:
        _pytest.exit(
            f"REFUSED: another pytest session (pid {holder}) holds this "
            f"repository's suite lock. Concurrent runs interfere - they spawn "
            f"real subprocesses and drive timed barriers - and the numbers "
            f"they produce are void, not merely noisy. Wait, or remove "
            f"{_LOCK} if that pid is gone.",
            returncode=2)
    # THE BACKSTOP, for a run that never took the lock. Checked second because
    # the lock is the cheap and exact answer and this one shells out.
    stranger = _foreign_pytest()
    if stranger:
        _pytest.exit(
            f"REFUSED: pytest (pid {stranger[0]}) is running against a "
            f"worktree of this repository without holding {_LOCK}. Its run and "
            f"this one would contend for the same cores, and both sets of "
            f"numbers would be void. Wait for it, or have that suite adopt "
            f"`run_alone`.",
            returncode=2)
    _LOCK.write_text(str(_os.getpid()))
    try:
        yield
    finally:
        try:
            if _LOCK.exists() and _LOCK.read_text().strip() == str(_os.getpid()):
                _LOCK.unlink()
        except OSError:
            pass


# ── the frozen direct-route config ──────────────────────────────────────────
# A fixture rather than an import, because the tests directory is not on
# `sys.path` for a bare `import` and three call sites should not each grow a
# path manipulation to work around that.
import importlib.util as _ilu                                  # noqa: E402

_spec = _ilu.spec_from_file_location(
    "gauntlet_direct_route_precondition",
    pathlib.Path(__file__).resolve().parent / "direct_route_precondition.py")
_direct_route = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_direct_route)


@pytest.fixture()
def runnable_direct_route():
    """The native entrypoint, or a refusal BY NAME before the ten second wait.

    See `direct_route_precondition.py` for what is missing and why this is a
    refusal rather than a failure.
    """
    from probe_support import ARCHIVE

    return _direct_route.refuse_unless_runnable(ARCHIVE)
