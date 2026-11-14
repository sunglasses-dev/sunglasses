"""The folder a command is started in never decides what sunglasses imports.

`python -m module` and `python -c code` put the current folder first on `sys.path`. Every place
sunglasses starts Python (the scan worker, the proxy worker, the PreToolUse hook line `init`
writes) used to read the folder being scanned, or the agent's project folder, as part of Python:
a `json.py` or `_json.py` there ran instead of the standard library. These tests plant such
files and check, both ways, that nothing runs and the result does not change.

Every plant writes a marker file OUTSIDE the planted folder, so "nothing ran" is a file that does
not exist, and each group has a control that DOES run the plant so the test can fail.
"""

import json
import os
import shlex
import site
import subprocess
import sys
import textwrap

import pytest

from sunglasses import _launch
from sunglasses.firewall import HOOK_MARKER, build_hook_entry

ROOT = _launch.package_root()
PLANTS = ("json", "_json", "sunglasses_pkg")      # the package plant is its own case below (it only matters off the path)
CLEAN_README = "A short note about the weather. Nothing here is an instruction.\n"


def _plant(folder, marker, names=("json", "_json")):
    """Files named like standard-library modules, each leaving a mark when it runs."""
    for name in names:
        (folder / f"{name}.py").write_text(
            f"open({str(marker)!r}, 'a').write({name!r} + ' ran\\n')\n", encoding="utf-8")


@pytest.fixture
def planted(tmp_path):
    folder = tmp_path / "project"
    folder.mkdir()
    marker = tmp_path / "MARK"
    (folder / "README.md").write_text(CLEAN_README, encoding="utf-8")
    _plant(folder, marker)
    return folder, marker


def _env(**extra):
    # The package comes from the checkout the way an editable install would give it, on purpose.
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp"),
           "PYTHONPATH": ROOT}
    env.update(extra)
    return env


def _run(argv, folder, stdin="", env=None, shell=False):
    return subprocess.run(argv, input=stdin, capture_output=True, text=True, cwd=str(folder),
                          env=env or _env(), shell=shell, timeout=120)


def test_control_a_plain_command_in_the_folder_does_run_the_plant(planted):
    folder, marker = planted
    _run([sys.executable, "-c", "import json"], folder)
    assert marker.exists(), "the plant must be able to run, or the tests below prove nothing"


# ---- the scan worker ------------------------------------------------------------------------

_CONSOLE = ("import sys; sys.path[:1] = []; sys.argv = ['sunglasses', 'scan', '--file', 'README.md', '--json']; "
            "from sunglasses.cli import main; main()")     # the console script never has the folder on the path either


@pytest.mark.parametrize("names", [("json",), ("_json",), ("json", "_json", "re")])
def test_scan_with_planted_modules_gives_the_same_answer_and_runs_none(tmp_path, names):
    clean = tmp_path / "clean"; clean.mkdir(); (clean / "README.md").write_text(CLEAN_README, encoding="utf-8")
    dirty = tmp_path / "dirty"; dirty.mkdir(); (dirty / "README.md").write_text(CLEAN_README, encoding="utf-8")
    marker = tmp_path / "MARK"
    _plant(dirty, marker, names)
    want = _run([sys.executable, "-c", _CONSOLE], clean)
    got = _run([sys.executable, "-c", _CONSOLE], dirty)
    assert not marker.exists(), f"a planted module ran inside the scan: {marker.read_text() if marker.exists() else ''}"
    assert got.returncode == want.returncode == 0, (want.stderr[-300:], got.stderr[-300:])
    pick = lambda out: {k: v for k, v in json.loads(out.stdout).items() if k in ("decision", "severity", "channel", "inspection_complete")}
    assert pick(got) == pick(want) and pick(got)["decision"] == "allow"


def test_scan_with_a_planted_sunglasses_folder_never_runs_it(tmp_path):
    dirty = tmp_path / "dirty"; dirty.mkdir(); (dirty / "README.md").write_text(CLEAN_README, encoding="utf-8")
    marker = tmp_path / "MARK"
    (dirty / "sunglasses").mkdir()
    (dirty / "sunglasses" / "__init__.py").write_text(f"open({str(marker)!r}, 'a').write('pkg ran')\n", encoding="utf-8")
    got = _run([sys.executable, "-c", _CONSOLE], dirty)
    assert got.returncode == 0 and json.loads(got.stdout)["decision"] == "allow", got.stderr[-300:]
    assert not marker.exists()


def test_the_old_worker_launch_is_also_covered_by_the_package_guard(planted):
    """Belt and braces: even the old `-m sunglasses.scan_worker` form (a parent from before this fix
    never starts it, but a person can type it) drops the implicit folder entry before the package imports."""
    folder, marker = planted
    _run([sys.executable, "-B", "-m", "sunglasses.scan_worker"], folder, stdin="")
    assert not marker.exists()


def test_the_worker_argv_is_the_guarded_form():
    argv = _launch.child_argv("sunglasses.scan_worker", flags=("-B",))
    assert argv[0] == sys.executable and argv[1] == "-B"
    assert ("-P" in argv) == (sys.version_info >= (3, 11))
    assert argv[-2] == "-c" and "-m" not in argv
    from sunglasses import scan_worker
    from sunglasses.proxy import worker_process
    assert scan_worker.default_argv()[-2:-1] == ["-c"] and "sunglasses.scan_worker" in scan_worker.default_argv()[-1]
    assert worker_process.default_argv()[-2:-1] == ["-c"] and "sunglasses._proxy_worker" in worker_process.default_argv()[-1]


# ---- the hook line `init` writes ------------------------------------------------------------

def _hook_forms():
    entry = build_hook_entry()["hooks"][0]["command"]
    start_up_line = " ".join(shlex.quote(w) for w in [sys.executable, "-c", _launch.bootstrap(HOOK_MARKER)])
    return {"as written for this python": entry, "start-up line (3.9, 3.10 and any other interpreter)": start_up_line}


@pytest.mark.parametrize("form", list(_hook_forms()))
def test_the_hook_line_runs_the_firewall_and_none_of_the_plants(planted, form):
    folder, marker = planted
    command = _hook_forms()[form]
    done = _run(command, folder, stdin="{}", shell=True)
    assert not marker.exists(), "a planted module ran inside the hook"
    assert "firewall" in (done.stdout + done.stderr).lower() or done.returncode in (0, 2), done.stderr[-300:]


def test_the_hook_line_is_dash_p_on_311_and_up_and_the_start_up_line_below(monkeypatch):
    for version, flag in (((3, 9, 18), False), ((3, 10, 14), False), ((3, 11, 0), True), ((3, 14, 3), True)):
        monkeypatch.setattr(sys, "version_info", version + ("final", 0))
        words = shlex.split(_launch.command_line("/usr/bin/python3", HOOK_MARKER, running=True))
        assert (words[1:4] == ["-P", "-m", HOOK_MARKER]) is flag, (version, words[:4])
        if not flag:
            assert words[1] == "-c" and "runpy" in words[2]
    # an interpreter whose version is unknown here always gets the line that works on every version
    words = shlex.split(_launch.command_line("/opt/other/python3", HOOK_MARKER, running=False))
    assert words[1] == "-c" and HOOK_MARKER in words[2]


def test_an_older_hook_line_written_before_this_fix_still_runs_no_json_or_underscore_json_plant(planted):
    """Command lines already in people's settings files say `python -m sunglasses.firewall`. After an
    upgrade the package drops the implicit folder entry first thing, so the modules imported after
    that come from Python. Stated limit: a `sunglasses` folder in the project is found before any of
    our code runs, and on 3.9 and 3.10 `re` is already imported by then; re-running `sunglasses init`
    writes the new line."""
    folder, marker = planted
    done = _run([sys.executable, "-m", HOOK_MARKER], folder, stdin="{}")
    assert not marker.exists(), "the old hook line ran a planted module after the upgrade"
    assert done.returncode in (0, 2), done.stderr[-300:]


def test_a_program_that_only_imports_sunglasses_keeps_its_own_path(tmp_path):
    (tmp_path / "mypkg").mkdir()
    (tmp_path / "mypkg" / "__init__.py").write_text("import sunglasses\nimport helper\nprint('own ok', helper.X)\n", encoding="utf-8")
    (tmp_path / "mypkg" / "__main__.py").write_text("", encoding="utf-8")
    (tmp_path / "helper.py").write_text("X = 7\n", encoding="utf-8")
    done = _run([sys.executable, "-m", "mypkg"], tmp_path)
    assert done.returncode == 0 and "own ok 7" in done.stdout, done.stderr[-300:]


# ---- what the start-up line does, and does not do ------------------------------------------

def test_the_start_up_line_drops_only_the_implicit_entry_and_keeps_pythonpath(tmp_path):
    """A module reachable through PYTHONPATH still runs; the same name in the current folder does not."""
    wanted, here = tmp_path / "wanted", tmp_path / "here"
    wanted.mkdir(); here.mkdir()
    (wanted / "standin.py").write_text("print('from PYTHONPATH')\n", encoding="utf-8")
    (here / "standin.py").write_text("print('from the current folder')\n", encoding="utf-8")
    done = _run([sys.executable, "-c", _launch.bootstrap("standin")], here, env=_env(PYTHONPATH=str(wanted)))
    assert done.stdout.strip() == "from PYTHONPATH", done.stderr[-300:]


def test_dash_p_and_the_start_up_line_behave_the_same(tmp_path):
    if sys.version_info < (3, 11):
        pytest.skip("-P needs 3.11")
    wanted, here = tmp_path / "wanted", tmp_path / "here"
    wanted.mkdir(); here.mkdir()
    (wanted / "standin.py").write_text("import sys; print(sys.argv[1:])\n", encoding="utf-8")
    (here / "standin.py").write_text("print('wrong')\n", encoding="utf-8")
    a = _run([sys.executable, "-P", "-m", "standin", "x", "--", "y"], here, env=_env(PYTHONPATH=str(wanted)))
    b = _run([sys.executable, "-c", _launch.bootstrap("standin"), "x", "--", "y"], here, env=_env(PYTHONPATH=str(wanted)))
    assert a.stdout == b.stdout == "['x', '--', 'y']\n", (a.stderr[-200:], b.stderr[-200:])


def test_a_user_site_install_still_imports_and_dash_i_would_not(tmp_path):
    if not site.ENABLE_USER_SITE:
        pytest.skip("this interpreter has no user site (a virtual environment)")
    base = tmp_path / "userbase"
    probe = subprocess.run([sys.executable, "-c", "import site; print(site.getusersitepackages())"],
                           capture_output=True, text=True, env={"PATH": os.environ.get("PATH", ""), "PYTHONUSERBASE": str(base)})
    usersite = probe.stdout.strip()
    os.makedirs(os.path.join(usersite, "usermod"))
    with open(os.path.join(usersite, "usermod", "__main__.py"), "w", encoding="utf-8") as f:
        f.write("print('user site ok')\n")
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path), "PYTHONUSERBASE": str(base)}
    forms = [[sys.executable, "-c", _launch.bootstrap("usermod")]]
    if sys.version_info >= (3, 11):
        forms.append([sys.executable, "-P", "-m", "usermod"])
    for argv in forms:
        done = _run(argv, tmp_path, env=env)
        assert done.stdout.strip() == "user site ok", (argv[:3], done.stderr[-200:])
    assert _run([sys.executable, "-I", "-m", "usermod"], tmp_path, env=env).returncode != 0, \
        "control: -I drops the user site, which is why it is not used"


# ---- a child must still find the package when only the parent could ------------------------

def test_a_child_finds_an_uninstalled_checkout_through_the_root_the_parent_hands_it(tmp_path):
    """The package is not installed in this environment: only the parent's root makes it importable, and
    it goes at the END of the path. A `sunglasses` folder in the current folder is never used."""
    venv = tmp_path / "venv"
    made = subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], capture_output=True, text=True)
    if made.returncode != 0:
        pytest.skip("cannot make a virtual environment here")
    py = str(venv / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python"))
    folder = tmp_path / "work"; folder.mkdir()
    marker = tmp_path / "MARK"
    (folder / "sunglasses").mkdir()
    (folder / "sunglasses" / "__init__.py").write_text(f"open({str(marker)!r}, 'a').write('planted pkg ran')\n", encoding="utf-8")
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path)}
    nothing = subprocess.run([py, "-c", "import sunglasses"], capture_output=True, text=True, cwd=str(folder), env=env)
    # (control: with the folder on the path the plant is what `import sunglasses` finds)
    assert marker.exists() and nothing.returncode == 0
    marker.unlink()
    argv = [py, *(["-P"] if sys.version_info >= (3, 11) else []), "-c", _launch.bootstrap("sunglasses", root=ROOT), "--version"]
    done = subprocess.run(argv, capture_output=True, text=True, cwd=str(folder), env=env, timeout=120)
    assert done.returncode == 0 and "sunglasses" in (done.stdout + done.stderr).lower(), done.stderr[-300:]
    assert not marker.exists(), "the planted sunglasses folder was imported"
    assert "append(" in _launch.bootstrap("sunglasses", root=ROOT), "the root is added to the END of the path"
