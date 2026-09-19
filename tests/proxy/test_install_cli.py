"""T10.R4/R5 at the CLI, through a real subprocess.

Exit codes follow AGENTS.md: 0 clean · 1 threat · 2 usage or operational error ·
3 incomplete inspection, and `0` and `3` must never collapse into each other.

`install` and `uninstall` never default to a path in the user's home. This
repo's CLAUDE.md records the hazard directly: `sunglasses init` writing into a
real settings file once inspected an agent's own subsequent tool calls. A wiring
command whose default target is `~/.claude.json` is the same hazard with a
different file, so the default is the project `.mcp.json` in the working
directory and anything else is explicit.
"""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

import pytest

from sunglasses import install as inst

REPO = str(pathlib.Path(__file__).resolve().parents[2])

RAW_CONFIG = (
    '{\n'
    '  "mcpServers": {\n'
    '    "github": {\n'
    '      "args": ["-y", "server-github"],\n'
    '      "command": "npx"\n'
    '    }\n'
    '  }\n'
    '}'
)


def sg(*args, cwd, home, pkgroot=None):
    """PYTHONPATH is pinned to the repo on purpose, or to `pkgroot` when a test
    needs to decide for itself whether the proxy entry point exists (F3).

    Without it these tests run `-m sunglasses.cli` from a tmp cwd, the import
    fails before argparse is ever reached, and every assertion of the form
    "invalid choice not in stderr" passes against a process that never started.
    Three of these tests passed that way before this line existed. Installed
    versus tree, the Sep-14 lesson, inside my own harness.
    """
    env = dict(os.environ, SUNGLASSES_HOME=str(home),
               PYTHONPATH=str(pkgroot) if pkgroot else REPO,
               PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-B", "-m", "sunglasses.cli", *args],
                          cwd=str(cwd), env=env, capture_output=True, text=True)


def _package_copy(dest, *, with_artifact):
    """A real copy of the package, because `resolve_artifact` calls
    `pathlib.Path(__file__).resolve().parent` and `resolve()` walks a symlink
    straight back to the original tree, so a symlink farm would shadow nothing.

    The artifact written here is this test's own fixture. It is deliberately
    NOT #168's `proxy/__main__.py`: a control that borrows another branch's
    file is a control that changes meaning when that branch does.
    """
    dest.mkdir(parents=True, exist_ok=True)
    pkg = dest / "sunglasses"
    shutil.copytree(pathlib.Path(REPO) / "sunglasses", pkg,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    entry = pkg / "proxy" / "__main__.py"
    if with_artifact:
        entry.parent.mkdir(parents=True, exist_ok=True)
        entry.write_text("# this test's fixture entry point, not #168's\n",
                         encoding="utf-8")
    elif entry.exists():
        entry.unlink()
    assert entry.is_file() is with_artifact
    return dest, entry


@pytest.fixture(scope="module")
def pkg_absent(tmp_path_factory):
    return _package_copy(tmp_path_factory.mktemp("pkg_absent"), with_artifact=False)


@pytest.fixture(scope="module")
def pkg_present(tmp_path_factory):
    return _package_copy(tmp_path_factory.mktemp("pkg_present"), with_artifact=True)


def _tree_digests(root):
    """Every file under `root`, by path and content digest."""
    out = {}
    for f in sorted(pathlib.Path(root).rglob("*")):
        if f.is_file() and "__pycache__" not in f.parts:
            out[str(f.relative_to(root))] = hashlib.sha256(f.read_bytes()).hexdigest()
    return out


def test_the_harness_actually_reaches_the_cli(tmp_path):
    """Guard on the guard: if this fails, every other test in this file is
    asserting against a process that died on import.

    Asserts on output only our CLI emits. Round 1 asserted `returncode == 0`
    and "No module named" absent, which an empty `sys.exit(0)` satisfies.

    ANCHORED ON THE SUBCOMMAND NAMES, NOT ON HELP PROSE. This row used to assert
    the `install` help string, and a correction to that string's WORDING broke
    the guard while the harness was working perfectly -- the guard reported on
    the sentence rather than on the thing it exists to prove. Command names are
    a contract and change deliberately; help prose is written to be rewritten.
    An empty `sys.exit(0)` still fails this, which is the failure it was built
    for.
    """
    r = sg("--help", cwd=tmp_path, home=tmp_path / "h")
    assert r.returncode == 0, r.stderr
    assert "No module named" not in r.stderr
    for command in ("firewall-hook", "install", "uninstall"):
        assert command in r.stdout, f"{command} missing from --help"


@pytest.fixture
def project(tmp_path):
    (tmp_path / ".mcp.json").write_text(RAW_CONFIG, encoding="utf-8")
    return tmp_path


def test_install_is_a_real_subcommand(project, tmp_path, pkg_absent):
    """Positive evidence: the refusal diagnostic our install prints. "invalid
    choice" being absent is also true of a process that never started.

    F3, FOURTH ROW. I named three rows from reading their docstrings and the
    measurement named a different three, which is the whole lesson again: this
    one says nothing about the artifact and was still green only because it
    was absent. Its positive evidence is the string "SUNGLASSES install",
    printed by the refusal; a SUCCEEDING install prints "Wrapped ..." instead,
    so with #168's entry point on main the row went red while looking
    unrelated to it. The absence it needs is now constructed like the others."""
    root, _ = pkg_absent
    r = sg("install", "github", cwd=project, home=tmp_path / "h", pkgroot=root)
    assert "invalid choice" not in r.stderr
    assert "SUNGLASSES install" in (r.stdout + r.stderr)


def test_uninstall_is_a_real_subcommand(project, tmp_path):
    r = sg("uninstall", "github", cwd=project, home=tmp_path / "h")
    assert "invalid choice" not in r.stderr
    assert "SUNGLASSES uninstall" in (r.stdout + r.stderr)


def test_install_exits_2_and_says_why_when_the_artifact_is_absent(
        project, tmp_path, pkg_absent):
    """F3. The absence is now BUILT BY THIS TEST rather than inherited from
    whatever the working tree happens to contain.

    On 8b16d96 this row was green because `sunglasses/proxy/__main__.py` did
    not exist anywhere yet, so it asserted a refusal that the build was
    producing for free. The declared merge order puts #168 ahead of this PR,
    and the day that file lands on main the row went red without a line of it
    changing. Now the refusal is driven from a package copy that genuinely
    lacks the entry point, so it means the same thing before and after."""
    root, _ = pkg_absent
    before = (project / ".mcp.json").read_bytes()
    r = sg("install", "github", cwd=project, home=tmp_path / "h", pkgroot=root)
    assert r.returncode == 2, r.stderr
    assert (project / ".mcp.json").read_bytes() == before
    assert "proxy entry point" in (r.stdout + r.stderr)


def test_install_never_writes_outside_the_named_config(project, tmp_path_factory, pkg_present):
    """F3. This row asserted "never writes outside" against a run that never
    wrote ANYTHING, because install refused at artifact resolution first. It
    proved the refusal twice and the property once, in the wrong direction.

    With the entry point present the install SUCCEEDS, so there is finally a
    write to be confined, and the confinement is checked by hashing every file
    in the project tree and in the package tree before and after."""
    root, entry = pkg_present
    # The home goes OUTSIDE the project on purpose. `project` IS `tmp_path`, so
    # the usual `tmp_path / "h"` puts the install RECORD inside the very tree
    # this row hashes, and "only the named config changed" would then be false
    # for a reason that has nothing to do with the property.
    home = tmp_path_factory.mktemp("sgh")
    project_before = _tree_digests(project)
    package_before = _tree_digests(root)

    r = sg("install", "github", cwd=project, home=home, pkgroot=root)

    assert r.returncode == 0, r.stdout + r.stderr
    assert (home / "proxy" / "installs" / "github.json").exists(), \
        "the install reported success and recorded nothing"

    # The named config is the ONLY file in the project that may differ.
    project_after = _tree_digests(project)
    changed = {k for k in set(project_before) | set(project_after)
               if project_before.get(k) != project_after.get(k)}
    assert changed == {".mcp.json"}, changed
    # And the package it wired itself to is untouched.
    assert _tree_digests(root) == package_before, "install wrote inside the package"

    # Present means WRAPPED, which is the state this file could not reach before.
    entry_json = json.loads((project / ".mcp.json").read_text())["mcpServers"]["github"]
    assert inst.classify(entry_json, artifact=entry) == "WRAPPED", entry_json


def test_uninstall_without_a_record_exits_2_and_does_not_mutate(project, tmp_path):
    before = (project / ".mcp.json").read_bytes()
    r = sg("uninstall", "github", cwd=project, home=tmp_path / "h")
    assert "invalid choice" not in r.stderr   # argparse also exits 2
    assert r.returncode == 2, r.stderr
    assert "SUNGLASSES uninstall refused" in r.stdout
    assert "no recorded install" in r.stdout
    assert (project / ".mcp.json").read_bytes() == before


def test_install_exits_2_when_it_cannot_proceed_at_all(tmp_path, pkg_present):
    """Renamed from "on an unreadable config", which it did not prove.

    ASTRA: on round 3 install refused at artifact resolution BEFORE it ever
    read the config, so a green result here was never evidence about
    config-read handling, and the docstring said so rather than fixing it.

    F3: with the entry point present the CLI now gets PAST resolution and
    fails on the missing config, which is the layer this row claimed to be
    about. It still proves exit 2 rather than 1, and a diagnostic rather than a
    traceback.
    """
    root, _ = pkg_present
    d = tmp_path / "empty"
    d.mkdir()
    r = sg("install", "github", cwd=d, home=tmp_path / "h", pkgroot=root)
    assert "invalid choice" not in r.stderr   # argparse also exits 2
    assert r.returncode == 2, r.stderr
    assert "SUNGLASSES install" in r.stdout
    assert "Traceback" not in r.stderr


def test_install_default_target_is_the_project_config_not_the_home_one(project, tmp_path):
    """The default must be the cwd's .mcp.json. Proven by pointing the process
    at a cwd with no config: it must fail on THAT path, never reach into HOME."""
    d = tmp_path / "bare"
    d.mkdir()
    r = sg("install", "github", cwd=d, home=tmp_path / "h")
    out = r.stdout + r.stderr
    assert ".mcp.json" in out
    assert ".claude.json" not in out


def test_install_accepts_an_explicit_config_path(tmp_path):
    other = tmp_path / "somewhere" / "custom.json"
    other.parent.mkdir()
    other.write_text(RAW_CONFIG, encoding="utf-8")
    d = tmp_path / "bare"
    d.mkdir()
    r = sg("install", "github", "--config", str(other), cwd=d, home=tmp_path / "h")
    assert "custom.json" in (r.stdout + r.stderr)


# ═══════════════════════════════════════════════════════════════════════════
# Round 7. ASTRA's R6_CHECK_RENAME_GAP, reshaped so the stimulus survives and
# the instrument does not deadlock.
#
# His row puts the racing install INSIDE our critical section and requires it to
# SUCCEED there: `child_install` is a synchronous `subprocess.run` called from a
# barrier inside `os.replace`, and its setup asserts `returncode == 0`. Under
# any mutual exclusion that is a circular wait, measured rather than argued: the
# parent holds the lock and waits for the child, the child waits for the lock
# (pids 47089 and 47097, 2026-09-17 04:31, in the PR body). No product-side
# timeout can break it, because the product is not the thing waiting.
#
# The stimulus he is actually testing -- a second install that completes while
# we are between our comparison and our rename -- is kept exactly. The only
# change is that his racer becomes a racer that CAN wait: spawned BEFORE the
# barrier, joined AFTER it. On a build without the lock it finishes inside our
# window and its work is destroyed, which is the defect. On this build it blocks
# for as long as we hold the lock and then completes, which is the fix.
# ═══════════════════════════════════════════════════════════════════════════


RACER = """
import os, pathlib, runpy, sys
pathlib.Path(sys.argv[1]).write_text("trying")
sys.argv = ["sunglasses", "install", "other", "--config", sys.argv[2]]
runpy.run_module("sunglasses.cli", run_name="__main__")
"""


def test_a_racing_install_that_can_wait_survives_our_rename(
        tmp_path, pkg_present):
    """R7-CHECK-RENAME-GAP. A compare and a rename are two operations, and a
    racer can publish between them. It is not enough to move the comparison
    closer to the rename: round 6 moved it as close as it goes, to the instant
    before the syscall, and this still failed. Two operations become one only
    under mutual exclusion, which is why the lock is on the transaction and the
    racer is one that can wait for it."""
    root, entry = pkg_present
    project = tmp_path / "project"
    project.mkdir()
    target = project / ".mcp.json"
    target.write_text(
        '{\n  "mcpServers": {\n'
        '    "github": {"command": "npx", "args": ["-y", "server-github"]},\n'
        '    "other": {"command": "other", "args": []}\n'
        '  }\n}',
        encoding="utf-8")
    home = tmp_path / "h"
    marker = tmp_path / "racer-trying"

    # The state a crash between the replace and the completion leaves: the
    # target is the wrapper, and a pending journal is the only claim on it.
    inst.install(target, "github", artifact=entry, home=home)
    _, rec_path, pending_path, _ = inst._record_paths(home, "github")
    rec = json.loads(rec_path.read_text())
    rec["state"] = "pending"
    pending_path.write_text(json.dumps(rec), encoding="utf-8")
    rec_path.unlink()

    env = dict(os.environ, SUNGLASSES_HOME=str(home), PYTHONPATH=str(root),
               PYTHONDONTWRITEBYTECODE="1")
    racer = subprocess.Popen(
        [sys.executable, "-B", "-c", RACER, str(marker), str(target)],
        cwd=str(project), env=env, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert marker.exists(), "the racer never started"

        rename = inst.os.replace
        entered = []

        def barrier(src, dst):
            if pathlib.Path(dst) == target and not entered:
                entered.append(True)
                # Inside the critical section, AFTER the comparison: the only
                # instant round 6 left. Give the racer every chance to finish.
                # Without the lock it does, and the next line destroys its work.
                stop = time.monotonic() + 2
                while time.monotonic() < stop and racer.poll() is None:
                    time.sleep(0.01)
            return rename(src, dst)

        inst.os.replace = barrier
        try:
            inst.uninstall(target, "github", home=home)
        except (inst.ConfigConflict, inst.ConfigIOError):
            pass
        finally:
            inst.os.replace = rename

        assert entered, "the rename boundary was never reached"
        out, err = racer.communicate(timeout=30)
    finally:
        if racer.poll() is None:
            racer.kill()
            racer.communicate()

    assert racer.returncode == 0, (
        f"the racing install did not succeed: {out}{err}")
    final = json.loads(target.read_bytes())["mcpServers"]["other"]
    assert inst.classify(final, artifact=entry) == "WRAPPED", (
        "a second install completed and reported success, and our rename put "
        "the file back the way it was before it ran")


def test_a_second_change_during_a_real_wait_is_seen_by_the_waiter(
        tmp_path, pkg_present):
    """The remainder of the review's step 3 that it did not reach: not a
    simulated wait, an actual one. A writer blocks on the lock while a second
    process changes the file twice, and what it publishes has to describe what
    is there when it finally gets in, not what it read before it waited."""
    root, entry = pkg_present
    project = tmp_path / "project"
    project.mkdir()
    target = project / ".mcp.json"
    target.write_text(
        '{\n  "mcpServers": {\n'
        '    "github": {"command": "npx", "args": []},\n'
        '    "other": {"command": "other", "args": []}\n'
        '  }\n}', encoding="utf-8")
    home = tmp_path / "h"
    inst.install(target, "github", artifact=entry, home=home)

    holder_ready = tmp_path / "holder-ready"
    release = tmp_path / "release"
    code = (
        "import sys, time, pathlib\n"
        "from sunglasses import install as i\n"
        "with i._exclusive(pathlib.Path(sys.argv[1])):\n"
        "    pathlib.Path(sys.argv[2]).touch()\n"
        "    while not pathlib.Path(sys.argv[3]).exists():\n"
        "        time.sleep(0.01)\n")
    holder = subprocess.Popen(
        [sys.executable, "-B", "-c", code,
         str(inst._lock_path(home, target)), str(holder_ready), str(release)],
        env=dict(os.environ, SUNGLASSES_HOME=str(home), PYTHONPATH=str(root),
                 PYTHONDONTWRITEBYTECODE="1"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 10
        while not holder_ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert holder_ready.exists(), "the holder never took the lock"

        real_write = inst._atomic_write
        changed = []

        def change_it_twice_then_wait(t, data):
            if not changed:
                # Set before the uninstall below, which writes through this
                # same boundary; a guard set afterwards re-enters.
                changed.append(None)
                # Two real changes to the file itself. Written directly rather
                # than through uninstall: uninstall takes the very lock the
                # holder is holding, so routing them through it would measure the
                # timeout instead of the re-derivation.
                doc = json.loads(target.read_bytes())
                doc["mcpServers"]["github"] = {"command": "npx", "args": []}
                target.write_text(json.dumps(doc, indent=2) + "\n",
                                  encoding="utf-8")
                doc = json.loads(target.read_bytes())
                doc["mcpServers"]["late"] = {"command": "late", "args": []}
                target.write_text(json.dumps(doc, indent=2) + "\n",
                                  encoding="utf-8")
                changed[0] = target.read_bytes()
                release.touch()
            return real_write(t, data)

        inst._atomic_write = change_it_twice_then_wait
        try:
            inst.install(target, "other", artifact=entry, home=home)
        finally:
            inst._atomic_write = real_write
        holder.communicate(timeout=30)
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.communicate()

    assert changed, "the change boundary was never reached"
    servers = json.loads(target.read_bytes())["mcpServers"]
    assert inst.classify(servers["other"], artifact=entry) == "WRAPPED"
    assert "late" in servers, "the waiter published over a change it never read"
    assert inst.classify(servers["github"], artifact=entry) != "WRAPPED", (
        "the waiter resurrected a wrapper that had been undone while it waited")
