"""CU-M7 and the CLI half of D3.

A cold run of the released 0.6.4 found two things a stranger cannot work out
alone. `sunglasses uninstall` restores the file and says nothing about the
approval, which outlives it on purpose (an approval is keyed on the server's
identity, so wrapping the same command from the same folder again needs no new
one). And `proxy` is a real command that `sunglasses --help` never lists, with
two spellings of `approve` in circulation.

What this pins, each one a behaviour a mutant must not survive.

  uninstall says approvals are kept, where they live and the exact command that
  revokes them, when there is one to revoke, and says nothing about them when
  there is not.
  `proxy` is listed in the top-level help.
  `approve` has one spelling in everything the package prints.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APPROVALS_NOTE = "kept on purpose"


def _run(args, *, home, cwd, stdin=None):
    # cwd is a scratch folder, so the tree under test is named explicitly. A
    # run that imported some other copy of the package would prove nothing.
    env = dict(os.environ, HOME=str(home), NO_COLOR="1", PYTHONPATH=str(REPO))
    env.pop("SUNGLASSES_HOME", None)
    return subprocess.run([sys.executable, "-m", "sunglasses.cli", *args],
                          capture_output=True, text=True, timeout=120,
                          env=env, cwd=str(cwd), input=stdin)


@pytest.fixture
def wrapped(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"echo": {"command": "python3",
                                 "args": ["-m", "sunglasses.proxy.echo_server"]}}},
        indent=2) + "\n")
    done = _run(["install", "echo"], home=home, cwd=proj)
    assert done.returncode == 0, done.stdout + done.stderr
    return home, proj


def _approvals_dir(home):
    return home / ".sunglasses" / "proxy" / "approvals"


def test_uninstall_with_an_approval_says_where_it_lives_and_how_to_revoke_it(wrapped):
    home, proj = wrapped
    folder = _approvals_dir(home)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / ("a" * 32 + ".json")).write_text("{}")
    out = _run(["uninstall", "echo"], home=home, cwd=proj)
    assert out.returncode == 0, out.stdout + out.stderr
    text = out.stdout
    assert APPROVALS_NOTE in text
    assert f"kept in {folder}" in text
    assert f"rm -r {folder}" in text
    # the restore itself is unchanged
    assert "Restored 'echo'" in text


def test_the_revoke_command_it_prints_really_revokes(wrapped):
    home, proj = wrapped
    folder = _approvals_dir(home)
    folder.mkdir(parents=True, exist_ok=True)
    record = folder / ("b" * 32 + ".json")
    record.write_text("{}")
    out = _run(["uninstall", "echo"], home=home, cwd=proj)
    printed = next(line.strip() for line in out.stdout.splitlines()
                   if line.strip().startswith("rm -r "))
    subprocess.run(printed, shell=True, check=True, env=dict(os.environ, HOME=str(home)))
    assert not record.exists()


def test_uninstall_with_no_approval_does_not_talk_about_approvals(wrapped):
    home, proj = wrapped
    folder = _approvals_dir(home)
    assert not folder.exists() or not list(folder.glob("*.json"))
    out = _run(["uninstall", "echo"], home=home, cwd=proj)
    assert out.returncode == 0, out.stdout + out.stderr
    assert APPROVALS_NOTE not in out.stdout
    assert "rm -r" not in out.stdout


@pytest.mark.skipif(os.geteuid() == 0, reason="root can list any directory")
def test_an_unlistable_approvals_folder_does_not_break_uninstall(wrapped):
    home, proj = wrapped
    folder = _approvals_dir(home)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / ("d" * 32 + ".json")).write_text("{}")
    folder.chmod(0o000)
    try:
        out = _run(["uninstall", "echo"], home=home, cwd=proj)
    finally:
        folder.chmod(0o700)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "Restored 'echo'" in out.stdout
    assert "Traceback" not in out.stderr


def test_a_refused_uninstall_does_not_print_the_approval_note(wrapped):
    home, proj = wrapped
    folder = _approvals_dir(home)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / ("c" * 32 + ".json")).write_text("{}")
    out = _run(["uninstall", "nothing-by-this-name"], home=home, cwd=proj)
    assert APPROVALS_NOTE not in out.stdout


def test_top_level_help_lists_proxy(tmp_path):
    out = _run(["--help"], home=tmp_path, cwd=tmp_path)
    assert out.returncode == 0
    listed = [line.split()[0] for line in out.stdout.splitlines()
              if line.startswith("    ") and line.split()]
    assert "proxy" in listed, out.stdout


def test_listing_proxy_did_not_change_what_the_word_does(tmp_path):
    """The alias still intercepts before argparse: no args is the proxy's own
    usage error, not argparse's."""
    out = _run(["proxy"], home=tmp_path, cwd=tmp_path)
    assert out.returncode == 2
    assert "sunglasses proxy approve" in out.stderr


def _approve_spellings():
    root = pathlib.Path(__file__).resolve().parent.parent / "sunglasses"
    hits = []
    for path in root.rglob("*.py"):
        if path.name == "patterns.py":
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "python -m sunglasses.proxy approve" in line:
                hits.append(f"{path.relative_to(root.parent)}:{number}")
    return hits


def test_approve_has_one_spelling_in_what_the_package_prints():
    assert _approve_spellings() == []
