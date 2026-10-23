"""The suite's own fixture (tests/conftest.py, `_no_trace_outlives_its_test`) puts the main thread's
trace function back after every test.

What this pins is that restoration: a test that sets a trace function does not hand it to the next
test, and an outer trace function that was in force before the test is the one in force after it.
It does not pin the slowdown the fixture exists for. A trace function set by a thread that has
ended leaves `sys.gettrace()` at None either way, so no state a test can read back tells the two
apart.

The check runs a real pytest in a directory of its own with a copy of tests/conftest.py, because
the thing under test is a fixture that applies to every other test in the run.
"""
import os
import pathlib
import shutil
import subprocess
import sys

TESTS = pathlib.Path(__file__).resolve().parent

CHILD = '''
import sys

def f(frame, event, arg):
    return f

def g(frame, event, arg):
    return g

def test_1_sets_a_trace_function():
    sys.settrace(f)
    assert sys.gettrace() is f

def test_2_finds_none_left():
    assert sys.gettrace() is {expected}
'''

OUTER = '''
import sys
import pytest

def g(frame, event, arg):
    return g

@pytest.fixture(autouse=True, scope="module")
def outer():
    sys.settrace(g)
    yield
    sys.settrace(None)
'''

UNCHANGED = '''
import sys

real = sys.settrace
calls = []

def test_1_changes_no_trace_function_and_watches_the_reset():
    start = sys.gettrace()
    calls.append(start)

    def recording(hook):
        calls.append(hook)
        real(hook)
    sys.settrace = recording

def test_2_the_reset_still_ran_with_the_trace_function_it_found():
    sys.settrace = real
    assert len(calls) == 2, calls
    assert calls[1] is calls[0], calls
'''


def _run_child(tmp_path, files):
    shutil.copy(TESTS / "conftest.py", tmp_path / "conftest.py")
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    env = {k: v for k, v in os.environ.items() if k not in ("CI_SHARD", "PYTEST_ADDOPTS")}
    env["PYTHONPATH"] = os.pathsep.join([str(TESTS), env.get("PYTHONPATH", "")])
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "addopts=",
         "--rootdir", str(tmp_path), str(tmp_path)],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)


def test_a_trace_function_set_in_one_test_is_gone_in_the_next(tmp_path):
    done = _run_child(tmp_path, {"test_none.py": CHILD.format(expected="None")})
    assert done.returncode == 0, done.stdout + done.stderr
    assert "2 passed" in done.stdout, done.stdout


def test_the_trace_function_in_force_before_a_test_is_the_one_after_it(tmp_path):
    body = CHILD.format(expected="g")
    outer = OUTER + body.replace("\ndef g(frame, event, arg):\n    return g\n", "\n", 1)
    done = _run_child(tmp_path, {"test_outer.py": outer})
    assert done.returncode == 0, done.stdout + done.stderr
    assert "2 passed" in done.stdout, done.stdout


def test_the_trace_function_is_put_back_even_when_the_test_changed_nothing(tmp_path):
    # The fixture calls sys.settrace on every teardown, equal or not. A fixture that skipped
    # the call when the saved and current functions match would pass the two tests above.
    done = _run_child(tmp_path, {"test_unchanged.py": UNCHANGED})
    assert done.returncode == 0, done.stdout + done.stderr
    assert "2 passed" in done.stdout, done.stdout
