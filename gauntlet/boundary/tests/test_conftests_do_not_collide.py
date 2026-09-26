"""Two conftests, two suites, one interpreter — and both must actually load.

`gauntlet/boundary/tests/conftest.py` and `gauntlet/report/tests/conftest.py`
were both registered as the module `conftest`. Under pytest's prepend import
mode the first one imported claims that name and THE OTHER IS NEVER LOADED, so
naming both suites in one invocation silently runs one of them with no exam
root, no module binding and no run-alone lock — and it looks like an ordinary
run while it does it.

Measured 2026-09-22 before the packages existed: with both suites on the command
line, exactly one `conftest` appeared in `sys.modules`.

The subprocess row is the one that matters. An in-process assertion can only see
the interpreter it is already in; this one actually runs both suites together
and reads what loaded.
"""
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[2]


def test_this_suites_conftest_is_not_registered_under_the_bare_name():
    """A bare `conftest` is a name two directories can both want.

    Package-qualified, they cannot collide at all, which is a structural fix
    rather than an ordering one.
    """
    ours = str(HERE / "conftest.py")
    names = [name for name, module in list(sys.modules.items())
             if getattr(module, "__file__", None) == ours]
    assert names, f"this suite's conftest {ours} is not in sys.modules at all"
    assert all("." in name for name in names), (
        f"this suite's conftest is registered as {names}. A bare 'conftest' is "
        "a name the report suite's conftest wants too, and whichever loads "
        "second is silently dropped.")


def test_both_gauntlet_conftests_load_in_one_invocation():
    """End to end, in a real subprocess, with both suites named at once.

    COLLECTION ONLY, deliberately. Running them would take the repository suite
    lock, and this test is itself running under pytest which already holds it —
    so a full run correctly refuses and the row would be measuring the guard
    instead of the collision.

    Collection is enough, because collection is where it broke. With both
    directories importing as `tests.conftest`, pytest raises
    ImportPathMismatchError and exits non-zero before a single test runs. That
    is the discriminating signal and it needs no lock.
    """
    import os

    done = subprocess.run(
        [sys.executable, "-m", "pytest",
         "gauntlet/boundary/tests/test_run_alone_lock.py",
         "gauntlet/report/tests/",
         "--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=str(REPO), capture_output=True, text=True, timeout=300,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    output = done.stdout + done.stderr

    assert "ImportPathMismatchError" not in output, (
        "the two conftests are fighting over one module name:\n"
        + output[-1200:])
    assert done.returncode == 0, output[-1200:]

    # AND BOTH SUITES WERE ACTUALLY COLLECTED. A green collection that found
    # only one of them would pass the assertions above and prove nothing.
    assert "gauntlet/boundary/tests/" in output, output[-600:]
    assert "gauntlet/report/tests/" in output, output[-600:]
