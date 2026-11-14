"""C1329. A wrapper written BEFORE the import-path fix starts the proxy with the bare
`-m sunglasses.proxy`, so a json.py in the folder the client runs it from ran first.

An upgrade cannot edit a user's config. What it can do, and what these tests pin:
  * `sunglasses install <name>` over an old wrapper re-writes it in the current form (the
    ordinary uninstall, then install; approvals are kept);
  * `sunglasses doctor` names an old wrapper the way it names an old hook, with the fix;
  * a failure between the two steps leaves the ORIGINAL entry in the file, and says so.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

from sunglasses import install as inst

REPO = str(pathlib.Path(__file__).resolve().parents[2])
RAW = '{\n  "mcpServers": {\n    "github": {\n      "args": ["-y", "server-github"],\n      "command": "npx"\n    }\n  }\n}'

# Runs the real CLI, but with the wrapper writer put back to the form written before the fix.
_OLD_INSTALL = (
    "import runpy, sys\n"
    "sys.path.insert(0, sys.argv[1]); sys.argv[1:2] = []\n"
    "from sunglasses import install as i\n"
    "i.launch_args = lambda: list(i.LAUNCH)\n"
    "runpy.run_module('sunglasses.cli', run_name='__main__', alter_sys=True)\n")
_CLI = (
    "import runpy, sys\n"
    "sys.path.insert(0, sys.argv[1]); sys.argv[1:2] = []\n"
    "runpy.run_module('sunglasses.cli', run_name='__main__', alter_sys=True)\n")


def _run(code, *args, cwd, home):
    env = dict(os.environ, HOME=str(home), SUNGLASSES_HOME=str(home), PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-B", "-c", code, REPO, *args], cwd=str(cwd), env=env,
                          capture_output=True, text=True, timeout=300)


@pytest.fixture
def project(tmp_path):
    (tmp_path / "proj").mkdir()
    cfg = tmp_path / "proj" / ".mcp.json"
    cfg.write_text(RAW, encoding="utf-8")
    return cfg


@pytest.fixture
def home(tmp_path):
    return tmp_path / "home"


def _entry(cfg):
    return json.loads(cfg.read_text())["mcpServers"]["github"]


@pytest.fixture
def old_wrapped(project, home):
    r = _run(_OLD_INSTALL, "install", "github", cwd=project.parent, home=home)
    assert r.returncode == 0, r.stderr + r.stdout
    assert _entry(project)["args"][:3] == ["-m", "sunglasses.proxy", "--"]
    return project


def test_install_again_over_an_old_wrapper_rewrites_it_to_the_current_form(old_wrapped, home):
    cfg = old_wrapped
    r = _run(_CLI, "install", "github", cwd=cfg.parent, home=home)
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Re-wrapped" in r.stdout
    args = _entry(cfg)["args"]
    assert args[:args.index("--")] == inst.launch_args()
    assert args[args.index("--") + 1:] == ["npx", "-y", "server-github"]
    assert inst.classify(_entry(cfg), artifact=inst.resolve_artifact()) == "WRAPPED"
    assert inst.launch_form(_entry(cfg)) == "OK"


def test_uninstall_after_a_rewrite_restores_the_original_file(old_wrapped, home):
    cfg = old_wrapped
    assert _run(_CLI, "install", "github", cwd=cfg.parent, home=home).returncode == 0
    r = _run(_CLI, "uninstall", "github", cwd=cfg.parent, home=home)
    assert r.returncode == 0, r.stderr + r.stdout
    assert cfg.read_text() == RAW


def test_install_over_a_current_wrapper_still_says_already_wrapped(project, home):
    assert _run(_CLI, "install", "github", cwd=project.parent, home=home).returncode == 0
    before = project.read_bytes()
    r = _run(_CLI, "install", "github", cwd=project.parent, home=home)
    assert r.returncode == 2 and "already wrapped" in (r.stdout + r.stderr)
    assert project.read_bytes() == before


def test_a_failure_between_the_two_steps_leaves_the_original_entry_and_says_so(old_wrapped, home, monkeypatch):
    cfg = old_wrapped
    from sunglasses.proxy.serve import install_records_home
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SUNGLASSES_HOME", str(home))
    monkeypatch.setattr(inst, "install",
                        lambda *a, **k: (_ for _ in ()).throw(inst.ConfigIOError("disk full")))
    with pytest.raises(inst.ConfigConflict) as e:
        inst.rewrite_launch_form(cfg, "github", artifact=inst.resolve_artifact(),
                                 home=install_records_home())
    assert "NOT wrapped" in str(e.value) and "sunglasses install github" in str(e.value)
    # the ORIGINAL entry is back in the file, not a half-written wrapper
    assert cfg.read_text() == RAW


def test_rewrite_refuses_what_is_not_an_old_wrapper(project, home):
    with pytest.raises(inst.ConfigConflict):
        inst.rewrite_launch_form(project, "github", artifact=inst.resolve_artifact(), home=home)


def test_doctor_names_an_old_wrapper_with_the_fix(old_wrapped, home):
    cfg = old_wrapped
    js = json.loads(_run(_CLI, "doctor", "--config", str(cfg), "--json", cwd=cfg.parent, home=home).stdout)
    rows = [r for r in js["inventory"] if r["name"] == "github"]
    assert rows and rows[0]["state"] == "WRAPPED" and rows[0]["launch"] == "OLD"
    text = _run(_CLI, "doctor", "--config", str(cfg), cwd=cfg.parent, home=home).stdout
    assert "Wrapper launch form" in text and "OLD FORM" in text and "sunglasses install github" in text


def test_doctor_is_silent_about_a_current_wrapper_and_the_exit_code_is_the_same(project, home):
    assert _run(_CLI, "install", "github", cwd=project.parent, home=home).returncode == 0
    new = _run(_CLI, "doctor", "--config", str(project), "--json", cwd=project.parent, home=home)
    assert all("launch" not in r for r in json.loads(new.stdout)["inventory"])
    assert "Wrapper launch form" not in _run(_CLI, "doctor", "--config", str(project),
                                             cwd=project.parent, home=home).stdout
