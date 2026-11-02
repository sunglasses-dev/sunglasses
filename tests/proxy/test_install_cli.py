"""The `install` and `uninstall` commands at the CLI, through a real subprocess.

Exit codes follow AGENTS.md: 0 clean · 1 threat · 2 usage or operational error ·
3 incomplete inspection, and `0` and `3` must never collapse into each other.

`install` and `uninstall` never default to a path in the user's home. A wiring
command whose default target is `~/.claude.json` would write into a real
settings file, so the default is the project `.mcp.json` in the working
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


# Child-side programs. Every child names the tree it must import in
# SG_TEST_TREE and puts that tree at the front of sys.path itself (`_PIN`).
# PYTHONPATH is set to the repository on purpose: an interpreter started in
# isolated mode ignores it, and one wrapped to put the repository first
# shadows it, so PYTHONPATH cannot choose between the repository and a package
# copy. A child that dropped the pin would import the repository, and the rows
# that built a copy to control which files exist would test the wrong tree.
_PIN = (
    "import os, sys\n"
    "sys.path.insert(0, os.environ['SG_TEST_TREE'])\n"
)
# Run `sunglasses.cli` the way `-m` would (module as __main__).
_RUN_CLI = _PIN + (
    "import runpy\n"
    "sys.argv = ['sunglasses.cli'] + sys.argv[1:]\n"
    "runpy.run_module('sunglasses.cli', run_name='__main__', alter_sys=True)\n"
)
_WHICH_TREE = _PIN + "import sunglasses\nprint(sunglasses.__file__)\n"


def _env(root, **extra):
    """The environment of a child that must import `root`."""
    return dict(os.environ, PYTHONPATH=REPO, SG_TEST_TREE=str(root),
                PYTHONDONTWRITEBYTECODE="1", **extra)


def _child(code, root, *args, cwd, home):
    return subprocess.run([sys.executable, "-B", "-c", code, *args],
                          cwd=str(cwd),
                          env=_env(root, HOME=str(home), SUNGLASSES_HOME=str(home)),
                          capture_output=True, text=True)


def sg(*args, cwd, home, pkgroot=None):
    """Run the CLI in a child process that imports `pkgroot`, or the repository.

    The child chooses its tree itself (`_PIN`); PYTHONPATH names the
    repository. `pkgroot` is for the tests that need to decide whether the
    proxy entry point exists.

    `HOME` is isolated alongside `SUNGLASSES_HOME` because the install record
    is stored under `serve.state_root()`, which is derived from HOME. With only
    the variable set, a row that installs would write its record into the real
    user's `~/.sunglasses` and read an empty sandbox. Isolate both, and assert
    the artefact landed inside the sandbox rather than trusting an empty
    directory.
    """
    return _child(_RUN_CLI, pkgroot if pkgroot else REPO, *args, cwd=cwd, home=home)


def _package_copy(dest, *, with_artifact):
    """A real copy of the package, because `resolve_artifact` calls
    `pathlib.Path(__file__).resolve().parent` and `resolve()` walks a symlink
    straight back to the original tree, so a symlink farm would shadow nothing.

    The artifact written here is this test's own fixture, not the
    repository's `proxy/__main__.py`: a control that borrows the product's file
    changes meaning when that file does.
    """
    dest.mkdir(parents=True, exist_ok=True)
    pkg = dest / "sunglasses"
    shutil.copytree(pathlib.Path(REPO) / "sunglasses", pkg,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    entry = pkg / "proxy" / "__main__.py"
    if with_artifact:
        entry.parent.mkdir(parents=True, exist_ok=True)
        entry.write_text("# this test's fixture entry point\n",
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
    """Every file under `root` except bytecode caches, by path and content digest."""
    out = {}
    for f in sorted(pathlib.Path(root).rglob("*")):
        if f.is_file() and "__pycache__" not in f.parts:
            out[str(f.relative_to(root))] = hashlib.sha256(f.read_bytes()).hexdigest()
    return out


def test_the_harness_actually_reaches_the_cli(tmp_path):
    """The harness reaches our CLI: the child prints our subcommand names.

    Asserts on output only our CLI emits, so an empty `sys.exit(0)` fails; a
    return code of 0 with "No module named" absent would not be enough.

    Anchored on the subcommand names, not on help prose: command names are a
    contract and change deliberately; help prose is written to be rewritten.
    """
    r = sg("--help", cwd=tmp_path, home=tmp_path / "h")
    assert r.returncode == 0, r.stderr
    assert "No module named" not in r.stderr
    for command in ("firewall-hook", "install", "uninstall"):
        assert command in r.stdout, f"{command} missing from --help"


def test_the_child_imports_the_tree_it_was_pinned_to(tmp_path, pkg_absent):
    """Every row that passes `pkgroot` assumes the child imported THAT copy.
    Asks a child which file it imported while PYTHONPATH names the repository,
    so a pin that did not take effect shows up as the repository's file."""
    root, entry = pkg_absent
    r = _child(_WHICH_TREE, root, cwd=tmp_path, home=tmp_path / "h")
    assert r.returncode == 0, r.stderr
    assert pathlib.Path(r.stdout.strip()).resolve() == (root / "sunglasses" / "__init__.py").resolve(), r.stdout
    assert not entry.exists()   # and that copy really has no entry point


def test_every_child_program_starts_with_the_pin():
    """The CLI runner, the racing install and the lock holder are separate
    programs; each must open with the shared pin."""
    for name, code in (("cli", _RUN_CLI), ("which", _WHICH_TREE),
                       ("racer", RACER), ("holder", HOLDER)):
        assert code.startswith(_PIN), f"the {name} child does not pin its tree"


@pytest.fixture
def project(tmp_path):
    (tmp_path / ".mcp.json").write_text(RAW_CONFIG, encoding="utf-8")
    return tmp_path


def test_install_is_a_real_subcommand(project, tmp_path, pkg_absent):
    """Positive evidence: the refusal diagnostic our install prints. "invalid
    choice" being absent is also true of a process that never started.

    The row says nothing about the artifact, so the absence it needs is built
    from a package copy without the entry point: a succeeding install prints
    "Wrapped ..." instead of the refusal."""
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
    """The absence is built by this test rather than inherited from whatever
    the working tree contains: the refusal is driven from a package copy that
    lacks `proxy/__main__.py`, so it means the same whether or not the
    repository has one."""
    root, _ = pkg_absent
    before = (project / ".mcp.json").read_bytes()
    r = sg("install", "github", cwd=project, home=tmp_path / "h", pkgroot=root)
    assert r.returncode == 2, r.stderr
    assert (project / ".mcp.json").read_bytes() == before
    assert "proxy entry point" in (r.stdout + r.stderr)


def test_install_never_writes_outside_the_named_config(project, tmp_path_factory, pkg_present):
    """With the entry point present the install succeeds, so there is a write
    to be confined. The confinement is checked by hashing every non-cache file
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
    assert (home / ".sunglasses" / "proxy" / "installs" / "github.json").exists(), \
        "the install reported success and recorded nothing"

    # The named config is the ONLY file in the project that may differ.
    project_after = _tree_digests(project)
    changed = {k for k in set(project_before) | set(project_after)
               if project_before.get(k) != project_after.get(k)}
    assert changed == {".mcp.json"}, changed
    # And the package it wired itself to is untouched.
    assert _tree_digests(root) == package_before, "install wrote inside the package"

    # Present means WRAPPED.
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
    """An install that cannot proceed at all exits 2 with a diagnostic.

    The package copy has the entry point, so the CLI gets past artifact
    resolution and fails on the missing config. It exits 2 rather than 1, and
    prints a diagnostic rather than a traceback.
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
# A racing install between our comparison and our rename.
#
# A second install that completes while we are between our comparison and our
# rename must not have its work destroyed. The racer is spawned BEFORE the
# barrier inside `os.replace` and joined AFTER it, so it can wait. A racer run
# synchronously from inside the barrier is a circular wait under any mutual
# exclusion: the parent holds the lock and waits for the child, the child waits
# for the lock. With the lock, the racer blocks for as long as we hold it and
# then completes.
# ═══════════════════════════════════════════════════════════════════════════


RACER = _PIN + """import pathlib, runpy
pathlib.Path(sys.argv[1]).write_text("trying")
sys.argv = ["sunglasses", "install", "other", "--config", sys.argv[2]]
runpy.run_module("sunglasses.cli", run_name="__main__")
"""

HOLDER = _PIN + """import time, pathlib
from sunglasses import install as i
with i._exclusive(pathlib.Path(sys.argv[1])):
    pathlib.Path(sys.argv[2]).touch()
    while not pathlib.Path(sys.argv[3]).exists():
        time.sleep(0.01)
"""


def test_a_racing_install_that_can_wait_survives_our_rename(
        tmp_path, pkg_present):
    """A compare and a rename are two operations, and a racer can publish
    between them. Moving the comparison closer to the rename does not close the
    gap. Two operations become one only under mutual exclusion, which is why
    the lock is on the transaction and the racer is one that can wait for it."""
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
    # The racer is the real CLI, so its root is HOME-derived
    # (`serve.install_records_home()`), while this process passes `home=`
    # explicitly. The two contend on one lock only if both name the same tree,
    # so the test builds it: HOME/.sunglasses.
    home_root = tmp_path / "h"
    home = home_root / ".sunglasses"
    marker = tmp_path / "racer-trying"

    # The state a crash between the replace and the completion leaves: the
    # target is the wrapper, and a pending journal is the only claim on it.
    inst.install(target, "github", artifact=entry, home=home)
    _, rec_path, pending_path, _ = inst._record_paths(home, "github")
    rec = json.loads(rec_path.read_text())
    rec["state"] = "pending"
    pending_path.write_text(json.dumps(rec), encoding="utf-8")
    rec_path.unlink()

    env = _env(root, HOME=str(home_root), SUNGLASSES_HOME=str(home))
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
                # Inside the critical section, after the comparison: give the
                # racer every chance to finish. Without mutual exclusion it
                # could, and the next line would destroy its work.
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
    """Not a simulated wait, an actual one. A writer blocks on the lock while
    a second process changes the file twice, and what it publishes has to
    describe what is there when it finally gets in, not what it read before it
    waited."""
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
    holder = subprocess.Popen(
        [sys.executable, "-B", "-c", HOLDER,
         str(inst._lock_path(home, target)), str(holder_ready), str(release)],
        env=_env(root, SUNGLASSES_HOME=str(home)),
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
                # Recorded first, so this hook acts once.
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

def test_install_says_what_happens_next_and_names_only_real_things(tmp_path, monkeypatch):
    """The success message has to be runnable, not reassuring.

    The commands, directories and field names it names are checked against the
    product here, because a message that names a command or a directory that
    does not exist is worse than silence: it sends the reader somewhere and
    they find nothing.

    It must NOT make a protection claim. A wrap succeeding says the launch path
    goes through us and nothing about what is enforced.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SUNGLASSES_HOME", str(home))
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(RAW_CONFIG, encoding="utf-8")

    r = sg("install", "github", "--config", str(cfg), cwd=tmp_path, home=home)
    assert r.returncode == 0, r.stderr
    out = r.stdout

    # 1. it says nothing is forwarded yet, and makes no protection claim
    assert "withheld until you approve" in out
    for claim in ("protected", "protects", "secure", "safe"):
        assert claim not in out.lower(), f"the message claims {claim!r}"

    # 2. the captures directory it names is the one the proxy actually uses
    from sunglasses.proxy.serve import state_root
    assert str(state_root() / "captures") in out

    # 3. the command it prints is a real command with real flags
    assert "sunglasses proxy approve" in out
    assert "--snapshot" in out
    from sunglasses.proxy import commands
    assert "approve" in commands.COMMANDS
    assert "--snapshot" in commands.USAGE

    # 4. the field names it tells the reader to look for are the ones the
    #    refusal actually carries
    from sunglasses.proxy import envelope
    built = envelope.withheld(
        request_id=1, reason_code="APPROVAL_REQUIRED", rule="S4",
        accepted=False, status="not_run", inspection_complete=False,
        inspected_utf8_bytes=0, observed_content_bytes=0, elapsed_ms=0,
        server_id="abc123", snapshot_sha256="d" * 64)
    for field in ("server_id", "snapshot_sha256"):
        assert field in out, f"the message does not name {field}"
        assert field in built["error"]["data"], f"the payload lacks {field}"
