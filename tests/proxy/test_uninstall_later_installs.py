"""`sunglasses uninstall` names the later installs that are the only reason the
restored file is not the original.

Two installs on one file, undone first-installed-first: after the first
uninstall the second install's wrapper is still in the file. The generic
"changed after the install" sentence reads as somebody else's edit, so the
line names the later install and says how to finish, in words. It prints no
command: a command is text for someone else's shell (quoting, option parsing
and the shell itself differ by platform), and the file and the server name are
already on screen.
"""
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

from sunglasses import install as inst

REPO = str(pathlib.Path(__file__).resolve().parents[2])

CANON = (json.dumps({"mcpServers": {
    "echo": {"command": "echo-server", "args": ["--stdio"]},
    "fetch": {"command": "fetch-server", "args": ["--stdio"]},
}}, indent=2) + "\n").encode("utf-8")

LATER = "later sunglasses install still wrapped here: "
CLOSING = "to restore the original"
WARNING = "not byte-identical"
CHANGED = "changed after the install"


def config_with(*names):
    return (json.dumps({"mcpServers": {
        n: {"command": n.replace(" ", "-") + "-server", "args": ["--stdio"]}
        for n in names}}, indent=2) + "\n").encode("utf-8")


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / ".mcp.json"
    p.write_bytes(CANON)
    return p


@pytest.fixture
def home(tmp_path):
    return tmp_path / "sgh"


@pytest.fixture
def artifact(tmp_path):
    a = tmp_path / "artifact" / "proxy_main.py"
    a.parent.mkdir(parents=True)
    a.write_text("# proxy entry point\n", encoding="utf-8")
    return a


def read(p):
    return pathlib.Path(p).read_bytes()


def foreign_edit(p):
    d = json.loads(read(p).decode("utf-8"))
    d["mcpServers"]["added-later"] = {"command": "other", "args": []}
    p.write_bytes((json.dumps(d, indent=2) + "\n").encode("utf-8"))


# ------------------------------------------------------------ library rows

def test_the_first_uninstall_names_the_later_install(cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)

    first = inst.uninstall(cfg, "echo", home=home)

    assert first.byte_exact is False
    assert first.later == ("fetch",)


def test_three_stacked_installs_name_every_later_install(cfg, home, artifact):
    cfg.write_bytes(config_with("echo", "fetch", "third"))
    for name in ("echo", "fetch", "third"):
        inst.install(cfg, name, artifact=artifact, home=home)

    assert inst.uninstall(cfg, "echo", home=home).later == ("fetch", "third")


def test_control_a_foreign_edit_on_top_is_not_blamed_on_the_later_install(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)
    foreign_edit(cfg)

    assert inst.uninstall(cfg, "echo", home=home).later == ()


def test_control_a_foreign_edit_between_the_installs_breaks_the_link(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    foreign_edit(cfg)
    inst.install(cfg, "fetch", artifact=artifact, home=home)

    assert inst.uninstall(cfg, "echo", home=home).later == ()


def test_control_an_ordinary_uninstall_names_no_later_install(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)
    assert inst.uninstall(cfg, "fetch", home=home).later == ()
    assert inst.uninstall(cfg, "echo", home=home).later == ()


def test_control_a_misplaced_record_does_not_name_a_server_that_is_not_wrapped(
        cfg, home, artifact):
    """Install `echo`, then `fetch`; move fetch's record to the name of a third
    server that is in the file but never wrapped. The digests still chain, so
    the name a record sits under is not taken as evidence."""
    cfg.write_bytes(config_with("echo", "fetch", "third"))
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)
    records = pathlib.Path(home) / "proxy" / "installs"
    (records / "fetch.json").rename(records / "third.json")

    assert inst.uninstall(cfg, "echo", home=home).later == ()


def test_control_the_named_server_must_still_be_the_wrapper_the_record_installed(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)
    rec = pathlib.Path(home) / "proxy" / "installs" / "fetch.json"
    body = json.loads(rec.read_text(encoding="utf-8"))
    body["installed_entry"] = {"command": "something-else", "args": []}
    rec.write_text(json.dumps(body, indent=2), encoding="utf-8")

    assert inst.uninstall(cfg, "echo", home=home).later == ()


def _three_with_one_command(cfg):
    entry = {"command": "same-server", "args": ["--stdio"]}
    cfg.write_bytes((json.dumps({"mcpServers": {n: dict(entry) for n in "cab"}},
                                indent=2) + "\n").encode("utf-8"))


def test_control_identical_wrappers_still_name_the_actual_later_installs(
        cfg, home, artifact):
    _three_with_one_command(cfg)
    for name in ("c", "a", "b"):
        inst.install(cfg, name, artifact=artifact, home=home)

    assert inst.uninstall(cfg, "c", home=home).later == ("a", "b")


def test_a_moved_record_is_not_taken_for_the_install_of_an_identical_wrapper(
        cfg, home, artifact):
    """Install c, a, b with one original entry, so the three wrappers are equal;
    put b's record under c's name. The digests still chain and the entry under
    that name is exactly the wrapper, so only the record's own retained-original
    path says whose install it was."""
    _three_with_one_command(cfg)
    for name in ("c", "a", "b"):
        inst.install(cfg, name, artifact=artifact, home=home)
    records = pathlib.Path(home) / "proxy" / "installs"
    (records / "b.json").replace(records / "c.json")

    assert inst.uninstall(cfg, "a", home=home).later == ()


def test_control_two_records_that_both_follow_the_file_are_a_fork_not_a_chain(
        cfg, home, artifact):
    """A copy of fetch's record under the name `third` also starts from the
    file echo left. Either could be the next install, so none is named."""
    cfg.write_bytes(config_with("echo", "fetch", "third"))
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)
    records = pathlib.Path(home) / "proxy" / "installs"
    body = json.loads((records / "fetch.json").read_text(encoding="utf-8"))
    body["original_bytes_path"] = str(records / "third.original")
    (records / "third.json").write_text(json.dumps(body, indent=2),
                                        encoding="utf-8")
    (records / "third.original").write_bytes(
        (records / "fetch.original").read_bytes())

    assert inst.uninstall(cfg, "echo", home=home).later == ()


def test_control_a_record_for_another_file_is_not_a_later_install_of_this_one(
        tmp_path, home, artifact):
    """File B starts from the bytes echo left in file A, then fetch is
    installed on B; B's result is copied over A. The digests chain and A holds
    the wrapper, but fetch was installed on B."""
    a = tmp_path / "a" / ".mcp.json"
    b = tmp_path / "b" / ".mcp.json"
    for p in (a, b):
        p.parent.mkdir()
        p.write_bytes(config_with("echo", "fetch"))
    inst.install(a, "echo", artifact=artifact, home=home)
    b.write_bytes(read(a))
    inst.install(b, "fetch", artifact=artifact, home=home)
    a.write_bytes(read(b))

    assert inst.uninstall(a, "echo", home=home).later == ()


# ---------------------------------------------------------------- CLI rows

def sg(*args, cwd, home):
    env = dict(os.environ, HOME=str(home), SUNGLASSES_HOME=str(home),
               PYTHONPATH=REPO, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-B", "-m", "sunglasses.cli", *args],
                          cwd=str(cwd), env=env, capture_output=True, text=True)


@pytest.fixture
def project(tmp_path):
    d = tmp_path / "work"
    d.mkdir()
    (d / ".mcp.json").write_bytes(CANON)
    return d


def _run(project, home, *steps):
    out = []
    for step in steps:
        r = sg(*step, cwd=project, home=home)
        assert r.returncode == 0, (step, r.stdout, r.stderr)
        out.append(r.stdout)
    return out


def _later_lines(stdout):
    return [line.strip() for line in stdout.splitlines()
            if line.strip().startswith("later sunglasses install")]


def test_one_later_install_prints_one_name_line_and_a_closing_line(
        project, tmp_path):
    out = _run(project, tmp_path / "h", ("install", "echo"),
               ("install", "fetch"), ("uninstall", "echo"))[2]

    assert _later_lines(out) == [LATER + "'fetch'"]
    assert "uninstall it the same way" in out and CLOSING in out
    assert CHANGED not in out and WARNING not in out


def test_two_later_installs_print_one_name_line_each_with_no_joining_word(
        project, tmp_path):
    (project / ".mcp.json").write_bytes(config_with("echo", "fetch", "third"))
    out = _run(project, tmp_path / "h", ("install", "echo"),
               ("install", "fetch"), ("install", "third"),
               ("uninstall", "echo"))[3]

    assert _later_lines(out) == [LATER + "'fetch'", LATER + "'third'"]
    assert all(" and " not in line for line in _later_lines(out))
    assert "uninstall them the same way" in out and out.count(CLOSING) == 1


@pytest.mark.parametrize("later", ["my server", "-dash", "it's", "a;b $c"])
def test_a_name_with_a_space_a_leading_dash_a_quote_or_a_shell_character_prints_as_its_repr(
        tmp_path, later):
    project = tmp_path / "work"
    project.mkdir()
    (project / ".mcp.json").write_bytes(config_with("echo", later))
    out = _run(project, tmp_path / "h", ("install", "echo"),
               ("install", "--", later), ("uninstall", "echo"))[2]

    assert _later_lines(out) == [LATER + repr(later)]


def test_no_runnable_command_is_printed_and_the_file_is_named_once(
        project, tmp_path):
    (project / ".mcp.json").write_bytes(config_with("echo", "fetch", "third"))
    out = _run(project, tmp_path / "h", ("install", "echo"),
               ("install", "fetch"), ("install", "third"),
               ("uninstall", "echo"))[3]

    assert not re.search(r"sunglasses\s+uninstall\s+-", out)
    assert "uninstall --" not in out and "-- fetch" not in out
    assert out.count(str(project / ".mcp.json")) == 1


def test_control_a_foreign_edit_keeps_the_generic_warning_on_step_one(
        project, tmp_path):
    home = tmp_path / "h"
    _run(project, home, ("install", "echo"), ("install", "fetch"))
    foreign_edit(project / ".mcp.json")
    out = _run(project, home, ("uninstall", "echo"))[0]

    assert CHANGED in out
    assert _later_lines(out) == [] and CLOSING not in out


def test_a_moved_record_prints_the_generic_warning_and_no_later_line(tmp_path):
    cfg = tmp_path / "c.json"
    _three_with_one_command(cfg)
    home = tmp_path / "h"
    for name in ("c", "a", "b"):
        assert sg("install", "--config", str(cfg), name, cwd=tmp_path,
                  home=home).returncode == 0
    (b_record,) = home.rglob("installs/b.json")
    b_record.replace(b_record.with_name("c.json"))

    out = sg("uninstall", "--config", str(cfg), "a", cwd=tmp_path, home=home)

    assert out.returncode == 0, (out.stdout, out.stderr)
    assert WARNING in out.stdout
    assert _later_lines(out.stdout) == [] and CLOSING not in out.stdout
