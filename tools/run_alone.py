"""One pytest run at a time, per repository — the decision, importable by any
suite in this repo.

SHARED ON PURPOSE. This started inside the gauntlet boundary suite's conftest
and could only protect that suite, which is precisely the defect: contention
comes from the OTHER suite. It lives here, at a neutral path on main and with
no imports beyond the standard library, so every conftest in the repository can
take the same lock. Two copies of this decision would be two answers to one
question.

ADOPTING IT, from any conftest:

    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[N] / "tools"))
    from run_alone import current_holder, foreign_pytest, repo_lock_path

Deliberately NOT inside `conftest.py`. A conftest is importable by pytest and
awkward for everything else, so decision logic living there can only be tested
by running the thing it guards. The guard's own rows could not import it
(`conftest` pulls the exam scaffold in at import time), which is how a guard
ends up with no tests at all.

WHY THE GUARD EXISTS. 2026-09-22: this suite was reported FLAKY on four runs
that returned 15, 17, 16 and 20 failures. It is not flaky — five sequential runs
of an untouched tree returned 15 every time with identical name sets and ZERO
movers. The spread came from running two and three pytest sessions at once:
these tests spawn real subprocesses, bind real files and drive timed barriers.
Concurrent runs invent failures in one direction and would hide real ones in the
other, so a number produced beside another run is VOID, not merely noisy.

The damage was not wasted runs. A false finding about the harness was written
up and reported. A rule in a document is read by whoever already knows it; this
refuses.

NOT `pgrep`. A pgrep for "pytest" matches the process doing the pgrep, and a
guard that reads its own command line measures itself (Sep-08: a wait loop that
never exited for exactly that reason). A pid in a lock file is checkable without
that hazard — it either names a live process or it does not.

REPO LEVEL, not suite level (2026-09-22, second pass). The first version keyed
on this suite's own directory, so it certified "I ran alone" while another
pytest on the same repository burned the same cores. That is a guard reporting
on a subject narrower than its name, and it cost a real measurement: four
sequential runs returned 13, 15, 12 and 12 failures, and the three tests that
moved are the three that drive subprocesses against a deadline. A foreign suite
(`tests/test_sd010_embedded_boundary.py`, another session's lane) was live
during the checks and the guard never saw it.

The key is `git rev-parse --git-common-dir`, which is the SAME path for every
worktree of one repository. Keying on the worktree root instead would let
eighty checkouts of this repo run eighty suites and call each one alone.

Matching on the command line does not work here and it is worth writing down
why: both suites are invoked with RELATIVE paths (`pytest tests/...`), so the
repository path appears in neither command line. The process's CWD is the
signal that actually exists, and `lsof -d cwd` reports it.
"""
from __future__ import annotations

import os
import pathlib
import subprocess

# The fallback only, for a checkout that is not a git repository. The real lock
# is `repo_lock_path()`, which is keyed on the whole repository.
LOCK = pathlib.Path(__file__).resolve().parent / ".suite-in-progress.lock"


def holder_alive(pid: int) -> bool:
    """True when `pid` names a live process.

    A STALE lock is reclaimed, never obeyed: a crashed run leaves its lock
    behind, and a guard that treats that as a live holder locks the suite out
    permanently — the failure mode where the guard becomes the outage.
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True            # exists, owned by another user
    return True


def current_holder(lock: pathlib.Path | None = None) -> int | None:
    """The live pid holding the suite, or None. Unreadable == not held."""
    lock = lock or LOCK
    try:
        pid = int(lock.read_text().strip() or 0)
    except (OSError, ValueError):
        return None
    if pid and pid != os.getpid() and holder_alive(pid):
        return pid
    return None


# ---------------------------------------------------------------------------
# Repo level. Everything above answers "is this suite already running"; the rest
# answers "is ANY suite running against this repository", which is the question
# that was actually being asked.

REPO_LOCK_NAME = "pytest-suite.lock"


def _git(*args: str, cwd: pathlib.Path | None = None) -> str | None:
    """A git answer, or None. Never raises: a guard that dies is an outage."""
    try:
        done = subprocess.run(("git",) + args, cwd=str(cwd or pathlib.Path.cwd()),
                              capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def common_git_dir(start: pathlib.Path | None = None) -> pathlib.Path | None:
    """The directory every worktree of this repository shares.

    `--git-common-dir` and not `--git-dir`: in a worktree the latter is that
    worktree's private directory, and keying on it would give every checkout
    its own lock and let all of them run at once.
    """
    start = start or pathlib.Path(__file__).resolve().parent
    answer = _git("rev-parse", "--git-common-dir", cwd=start)
    if not answer:
        return None
    path = pathlib.Path(answer)
    return path if path.is_absolute() else (start / path).resolve()


def repo_lock_path(start: pathlib.Path | None = None) -> pathlib.Path:
    """Where the repository wide lock lives, falling back to the suite lock.

    Outside a git checkout there is no repository to key on, and refusing to
    run at all would make the guard the outage. The suite local lock is the
    weaker guarantee, and it is the honest one to fall back to.
    """
    shared = common_git_dir(start)
    return (shared / REPO_LOCK_NAME) if shared else LOCK


def worktree_roots(start: pathlib.Path | None = None) -> list[pathlib.Path]:
    """Every checkout of this repository, as absolute paths."""
    start = start or pathlib.Path(__file__).resolve().parent
    listing = _git("worktree", "list", "--porcelain", cwd=start)
    if not listing:
        return []
    return [pathlib.Path(line[len("worktree "):])
            for line in listing.splitlines() if line.startswith("worktree ")]


def _cmdlines() -> dict[int, str]:
    try:
        done = subprocess.run(("ps", "-axo", "pid=,command="),
                              capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return {}
    out: dict[int, str] = {}
    for line in done.stdout.splitlines():
        pid, _, command = line.strip().partition(" ")
        try:
            out[int(pid)] = command
        except ValueError:
            continue
    return out


def _cwds(pids: list[int]) -> dict[int, pathlib.Path]:
    """Each pid's working directory. `lsof -d cwd` in ONE call, not one each."""
    if not pids:
        return {}
    try:
        done = subprocess.run(
            ("lsof", "-a", "-d", "cwd", "-Fpn", "-p", ",".join(map(str, pids))),
            capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return {}
    out: dict[int, pathlib.Path] = {}
    pid = None
    for line in done.stdout.splitlines():
        if line.startswith("p"):
            try:
                pid = int(line[1:])
            except ValueError:
                pid = None
        elif line.startswith("n") and pid is not None:
            out[pid] = pathlib.Path(line[1:])
    return out


def is_pytest_invocation(command: str) -> bool:
    """True when this command line IS pytest, not merely a mention of it.

    A substring test for "pytest" matches the shell wrapper that was asked to
    RUN pytest, and equally an `echo pytest` or a grep for the word. The guard
    refuses a whole suite on this answer, so a loose match here is a false kill
    waiting to happen: the process it names would be a shell that has already
    exited by the time anyone looks.

    So: argv[0] is the pytest launcher, or it is a python interpreter invoked
    with `-m pytest`.
    """
    argv = command.split()
    if not argv:
        return False
    # CASE FOLDED. macOS ships its framework interpreter as
    # `Python.app/Contents/MacOS/Python`, with a capital P, which is the
    # interpreter every run on this machine actually uses. A lowercase-only
    # test matched nothing here and the guard would have passed forever.
    name = os.path.basename(argv[0]).lower()
    if name.startswith("pytest"):
        return True
    if not name.startswith("python") and name != "py":
        return False
    for first, second in zip(argv, argv[1:]):
        if first == "-m" and second == "pytest":
            return True
    return False


def foreign_pytest(start: pathlib.Path | None = None) -> tuple[int, str] | None:
    """A live pytest running against this repository from another process group.

    OUR OWN PROCESS GROUP IS EXCLUDED, not just our own pid. The conftest that
    calls this runs INSIDE pytest, and a distributed run has workers besides;
    counting either would make the guard refuse its own session every time.

    Best effort on purpose. `ps` or `lsof` being unavailable returns None rather
    than raising, because the lock below is the authoritative coordination point
    and this is the backstop for a run that never took it.
    """
    roots = worktree_roots(start)
    if not roots:
        return None
    try:
        ours = os.getpgid(os.getpid())
    except OSError:                                          # pragma: no cover
        ours = None

    candidates = {}
    for pid, command in _cmdlines().items():
        if not is_pytest_invocation(command):
            continue
        if pid == os.getpid():
            continue
        try:
            if ours is not None and os.getpgid(pid) == ours:
                continue
        except OSError:
            pass
        candidates[pid] = command

    for pid, cwd in _cwds(sorted(candidates)).items():
        for root in roots:
            try:
                cwd.relative_to(root)
            except ValueError:
                continue
            return pid, candidates[pid]
    return None
